import os
import json
import threading
import time

import requests
from dotenv import load_dotenv
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User, Email, ActivityLog , Keyword
from utils import (
    parse_plain_email, extract_iocs, hash_bytes,
    nlp_predict, heuristic_flags_from_email, combine_ti_nlp,
    defang_url, defang_ip, defang_domain, vt_url_id
)

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change_me')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///email_security.db')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

BACKGROUND_QUEUE = []

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def enqueue(task):
    BACKGROUND_QUEUE.append(task)

def log_activity(email_id, source, message, level='info'):
    db.session.add(ActivityLog(email_id=email_id, source=source, message=message, level=level))
    db.session.commit()

# ---- Threat Intelligence lookups ----
def vt_lookup_url(u: str, key: str):
    if not key:
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}
    headers = {"x-apikey": key}
    # VT flow: submit URL to get id, then get analysis by id
    submit = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": u})
    if submit.status_code == 200:
        url_id = submit.json().get("data", {}).get("id", vt_url_id(u))
    else:
        url_id = vt_url_id(u)
    resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    return resp.json() if resp.status_code == 200 else {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}

def vt_lookup_ip(ip: str, key: str):
    if not key:
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}
    headers = {"x-apikey": key}
    resp = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)
    return resp.json() if resp.status_code == 200 else {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}

def vt_lookup_hash(h: str, key: str):
    if not key:
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}
    headers = {"x-apikey": key}
    resp = requests.get(f"https://www.virustotal.com/api/v3/files/{h}", headers=headers)
    return resp.json() if resp.status_code == 200 else {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}

def vt_lookup_domain(domain: str, key: str):
    if not key:
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}
    headers = {"x-apikey": key}
    resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
    return resp.json() if resp.status_code == 200 else {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}

def abuseipdb_check(ip: str, key: str):
    if not key:
        return {"data": {"abuseConfidenceScore": 0}}
    resp = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip},
        headers={"Key": key, "Accept": "application/json"}
    )
    return resp.json() if resp.status_code == 200 else {"data": {"abuseConfidenceScore": 0}}

def otx_lookup(kind: str, value: str, key: str):
    if not key:
        return {"pulse_info": {"pulses": []}}
    resp = requests.get(
        f"https://otx.alienvault.com/api/v1/indicators/{kind}/{value}/general",
        headers={"X-OTX-API-KEY": key}
    )
    return resp.json() if resp.status_code == 200 else {"pulse_info": {"pulses": []}}

# ---- Background worker ----
def worker():
    while True:
        try:
            if BACKGROUND_QUEUE:
                task = BACKGROUND_QUEUE.pop(0)
                process_task(task)
        except Exception as e:
            print("Worker error:", e)
        time.sleep(0.5)

def process_task(task):
    with app.app_context():
        email = db.session.get(Email, task['email_id'])
        user = db.session.get(User, task['user_id'])
        if not email or not user:
            return

        email.status = 'processing'
        email.progress = 10
        db.session.commit()
        log_activity(email.id, 'system', 'Processing started')

        # Extract IOCs
        iocs = extract_iocs(email.body_text or "")
        urls, ips, domains, hashes = iocs['urls'], iocs['ips'], iocs['domains'], iocs['hashes']

        email.urls_json = json.dumps(urls)
        email.domains_json = json.dumps(domains)
        email.received_ip = ','.join(ips)
        db.session.commit()

        # NLP
        nlp_score, nlp_label = nlp_predict(email.subject or "", email.body_text or "", urls)
        email.nlp_score = float(nlp_score)
        email.verdict = nlp_label
        email.progress = 40
        db.session.commit()

        # Threat Intelligence aggregation
        report = {"urls": [], "ips": {}, "domains": [], "hashes": []}

        # URLs
        for u in urls:
            vt_u = vt_lookup_url(u, key=user.virustotal_key)
            otx_u = otx_lookup('url', u, key=user.otx_key)
            vt_mal = vt_u.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) or 0
            otx_pulses = len(otx_u.get('pulse_info', {}).get('pulses', []))
            report["urls"].append({
                "url": u,
                "defanged": defang_url(u),
                "vt_malicious": vt_mal,
                "otx_pulses": otx_pulses
            })

        # IPs
        for ip in ips:
            vt_ip = vt_lookup_ip(ip, key=user.virustotal_key)
            abuse = abuseipdb_check(ip, key=user.abuseipdb_key)
            otx_ip = otx_lookup('ip', ip, key=user.otx_key)
            vt_mal = vt_ip.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) or 0
            abuse_score = abuse.get('data', {}).get('abuseConfidenceScore', 0) or 0
            otx_pulses = len(otx_ip.get('pulse_info', {}).get('pulses', []))
            report["ips"][ip] = {
                "defanged": defang_ip(ip),
                "vt_malicious": vt_mal,
                "abuse_score": abuse_score,
                "otx_pulses": otx_pulses
            }

        # Domains (added VT + OTX)
        for d in domains:
            vt_d = vt_lookup_domain(d, key=user.virustotal_key)
            otx_d = otx_lookup('domain', d, key=user.otx_key)
            vt_mal = vt_d.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) or 0
            pulses = len(otx_d.get('pulse_info', {}).get('pulses', []))
            flagged = vt_mal > 0 or pulses > 0
            report["domains"].append({
                "domain": d,
                "defanged": defang_domain(d),
                "vt_malicious": vt_mal,
                "otx_pulses": pulses,
                "status": "detected" if flagged else "clean"
            })

        # Hashes
        for h in hashes:
            vt_h = vt_lookup_hash(h, key=user.virustotal_key)
            otx_h = otx_lookup('hash', h, key=user.otx_key)
            vt_mal = vt_h.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) or 0
            pulses = len(otx_h.get('pulse_info', {}).get('pulses', []))
            report["hashes"].append({
                "hash": h,
                "vt_malicious": vt_mal,
                "otx_pulses": pulses
            })

        # Heuristics
        flags = heuristic_flags_from_email(
            subject=email.subject or "",
            sender=email.sender or "",
            body=email.body_text or "",
            urls=urls,
            headers_json=email.headers_json or "{}"
        )

        # Combine signals (include domain VT counts and pulses)
        vt_counts = (
            [u["vt_malicious"] for u in report["urls"]] +
            [h["vt_malicious"] for h in report["hashes"]] +
            [d["vt_malicious"] for d in report["domains"]]
        )
        otx_pulses_total = (
            sum(u["otx_pulses"] for u in report["urls"]) +
            sum(d["otx_pulses"] for d in report["domains"]) +
            sum(h["otx_pulses"] for h in report["hashes"])
        )
        abuse_max_score = max([v.get("abuse_score", 0) for v in report["ips"].values()] or [0])

        combined = combine_ti_nlp(
            nlp_score=email.nlp_score,
            nlp_label=email.verdict,
            vt_mal_counts=vt_counts,
            otx_pulses_total=otx_pulses_total,
            abuse_max_score=abuse_max_score,
            heuristic_flags=flags
        )

        email.analysis_report = json.dumps({"report": report, "combined": combined})
        email.verdict = combined["verdict"]
        email.status = 'done'
        email.progress = 100
        db.session.commit()
        log_activity(email.id, 'system', f'Processing done: {combined["verdict"]}')

# ---- Routes ----

@app.route('/training', methods=['GET', 'POST'])
@login_required
def training():
    if request.method == 'POST':
        email_id = request.form.get('email_id')
        label = request.form.get('label')

        # Save category keywords if checkboxes are ticked
        categories = ["urgency","credential_request","suspicious_links","attachment_pressure","impersonation"]
        for cat in categories:
            if request.form.get(cat):
                if not db.session.query(Keyword).filter_by(value=cat).first():
                    db.session.add(Keyword(category=cat, value=cat))

        # Save custom keywords
        raw_custom = request.form.get('custom_keywords','').strip()
        if raw_custom:
            items = [x.strip().lower() for x in raw_custom.replace(',', ' ').split() if x.strip()]
            for kw in items:
                if not db.session.query(Keyword).filter_by(value=kw).first():
                    db.session.add(Keyword(category="custom", value=kw))

        # Save notes as activity log
        notes = request.form.get('notes','').strip()
        if notes and email_id:
            log_activity(int(email_id), "training", f"Label={label}; Notes={notes}")

        db.session.commit()
        flash("Training data saved", "success")
        return redirect(url_for('training'))

    # ---- GET request: render training page with emails and existing keywords ----
    emails = db.session.query(Email).filter_by(user_id=current_user.id).order_by(Email.created_at.desc()).limit(100).all()
    keywords = db.session.query(Keyword).order_by(Keyword.category.asc(), Keyword.value.asc()).all()

    # Group keywords by category for display
    grouped_keywords = {}
    for k in keywords:
        grouped_keywords.setdefault(k.category, []).append(k.value)

    return render_template('training.html', emails=emails, keywords=grouped_keywords)


@app.route('/')
@login_required
def dashboard():
    emails = db.session.query(Email).filter_by(user_id=current_user.id).order_by(Email.created_at.desc()).all()
    phishing = sum(1 for e in emails if e.verdict == 'phishing')
    suspicious = sum(1 for e in emails if e.verdict == 'suspicious')
    clean = sum(1 for e in emails if e.verdict == 'clean')
    return render_template('dashboard.html', emails=emails, stats={"phishing": phishing, "suspicious": suspicious, "clean": clean})


@app.route('/report/delete/<int:email_id>', methods=['POST'])
@login_required
def delete_report(email_id):
    """Deletes an Email report and associated activity logs."""
    email_to_delete = db.session.get(Email, email_id)

    # 1. Check if the report exists and belongs to the current user
    if not email_to_delete or email_to_delete.user_id != current_user.id:
        flash("Report not found or access denied.", "danger")
        return redirect(url_for('reports'))

    try:
        # 2. Delete associated Activity Logs first
        ActivityLog.query.filter_by(email_id=email_id).delete()

        # 3. Delete the Email record
        db.session.delete(email_to_delete)
        db.session.commit()

        # 4. Success feedback
        flash(f"Report for subject '{email_to_delete.subject}' has been permanently deleted.", "success")
        return redirect(url_for('reports'))

    except Exception as e:
        db.session.rollback()
        # Log the error internally and show a generic message to the user
        print(f"Error deleting report {email_id}: {e}")
        flash("An error occurred during deletion. Please try again.", "danger")
        return redirect(url_for('report_detail', email_id=email_id))


# In app.py, add the following route near report_detail:
@app.route('/report/print/<int:email_id>')
@login_required
def print_report(email_id):
    """Renders a simplified view of the report optimized for printing."""
    email_row = db.session.get(Email, email_id)
    if not email_row or email_row.user_id != current_user.id:
        flash("Report not found or access denied", "danger")
        return redirect(url_for('reports'))
    try:
        report = json.loads(email_row.analysis_report or '{}')
    except Exception:
        report = {}
    logs = db.session.query(ActivityLog).filter_by(email_id=email_id).order_by(ActivityLog.ts.desc()).limit(100).all()
    # Note: Renders the new print_report.html template
    return render_template('report_print.html', email=email_row, report=report, logs=logs)

@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    if request.method == 'POST':
        f = request.files.get('email_file')
        if not f:
            flash("No file provided", "warning")
            return redirect(url_for('upload'))
        path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
        f.save(path)
        parsed = parse_plain_email(path)
        email_row = Email(
            user_id=current_user.id,
            filename=f.filename,
            subject=parsed.get('subject', ''),
            sender=parsed.get('from', ''),
            sender_domain=parsed.get('sender_domain', ''),
            received_ip=','.join(parsed.get('received_ips', [])),
            body_text=parsed.get('body_text', ''),
            urls_json=json.dumps(parsed.get('urls', [])),
            domains_json=json.dumps(parsed.get('domains', [])),
            headers_json=json.dumps(parsed.get('headers', {})),
            status='pending',
            progress=0
        )
        db.session.add(email_row)
        db.session.commit()
        enqueue({'email_id': email_row.id, 'user_id': current_user.id})
        flash("Uploaded. Analysis started.", "info")
        return redirect(url_for('report_detail', email_id=email_row.id))
    return render_template('upload.html')

@app.route('/reports')
@login_required
def reports():
    emails = db.session.query(Email).filter_by(user_id=current_user.id).order_by(Email.created_at.desc()).all()
    return render_template('reports.html', emails=emails)

@app.route('/report/<int:email_id>')
@login_required
def report_detail(email_id):
    email_row = db.session.get(Email, email_id)
    if not email_row or email_row.user_id != current_user.id:
        flash("Report not found or access denied", "danger")
        return redirect(url_for('reports'))
    try:
        report = json.loads(email_row.analysis_report or '{}')
    except Exception:
        report = {}
    logs = db.session.query(ActivityLog).filter_by(email_id=email_id).order_by(ActivityLog.ts.desc()).limit(100).all()
    return render_template('report_detail.html', email=email_row, report=report, logs=logs)

@app.route('/report/status/<int:email_id>')
@login_required
def report_status(email_id):
    email_row = db.session.get(Email, email_id)
    if not email_row:
        return jsonify({"status": "not_found"}), 404
    logs = db.session.query(ActivityLog).filter_by(email_id=email_id).order_by(ActivityLog.ts.desc()).limit(25).all()
    return jsonify({
        "status": email_row.status,
        "progress": email_row.progress,
        "verdict": email_row.verdict,
        "nlp_score": email_row.nlp_score or 0.0,
        "logs": [{"ts": l.ts.strftime('%H:%M:%S'), "level": l.level, "source": l.source, "message": l.message} for l in logs]
    })

@app.route('/settings', methods=['GET','POST'])
@login_required
def settings():
    if request.method == 'POST':
        current_user.virustotal_key = request.form.get('virustotal_key')
        current_user.abuseipdb_key = request.form.get('abuseipdb_key')
        current_user.otx_key = request.form.get('otx_key')
        new_pwd = request.form.get('password')
        if new_pwd:
            current_user.password = generate_password_hash(new_pwd)
        db.session.commit()
        flash("Settings updated", "success")
        return redirect(url_for('settings'))
    return render_template('settings.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email_addr = request.form['email'].strip().lower()
        pwd = request.form['password']
        u = db.session.query(User).filter_by(email=email_addr).first()
        if u and check_password_hash(u.password, pwd):
            login_user(u)
            return redirect(url_for('dashboard'))
        flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        u = User(
            username=request.form['username'].strip(),
            email=request.form['email'].strip().lower(),
            password=generate_password_hash(request.form['password'])
        )
        db.session.add(u)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Email or username already registered", "danger")
            return redirect(url_for('register'))
        flash("Registered! Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    threading.Thread(target=worker, daemon=True).start()
    app.run(host='0.0.0.0', debug=True)
