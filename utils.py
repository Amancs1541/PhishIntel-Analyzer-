import os
import re
import json
import math
import hashlib
import base64
from typing import List, Optional
from models import db , Keyword
from transformers import pipeline
import torch

# GPU-aware zero-shot NLP
device_id = 0 if torch.cuda.is_available() else -1
_zero_shot = pipeline("zero-shot-classification", model="facebook/bart-large-mnli", device=device_id)

PHISH_LABELS = ["phishing", "legitimate"]
PHISH_THRESHOLD = 0.65
SUSPICIOUS_FLOOR = 0.45

def nlp_predict(subject: str, body: str, urls: List[str]):
    text = (subject or "") + "\n" + (body or "") + "\n" + " ".join(urls or [])
    try:
        res = _zero_shot(text, PHISH_LABELS, multi_label=False)
        scores = {lbl.lower(): float(scr) for lbl, scr in zip(res["labels"], res["scores"])}
        phish_prob = scores.get("phishing", 0.0)
        verdict = "phishing" if phish_prob >= PHISH_THRESHOLD else ("suspicious" if phish_prob >= SUSPICIOUS_FLOOR else "clean")
        return phish_prob, verdict
    except Exception:
        return 0.5, "suspicious"

def extract_iocs(text: str):
    if not text:
        return {"urls": [], "ips": [], "domains": [], "hashes": []}
    urls = re.findall(r'https?://[^\s)>\]}]+', text)
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
    domains = re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', text)
    domains = [d for d in domains if not d.startswith('http')]
    hashes = re.findall(r'\b[a-f0-9]{64}\b', text.lower())
    return {"urls": urls, "ips": ips, "domains": domains, "hashes": hashes}

def parse_plain_email(path: str):
    subject, sender, body_lines = "", "", []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        for line in lines[:30]:
            low = line.lower()
            if low.startswith("subject:"):
                subject = line.split(":", 1)[1].strip()
            elif low.startswith("from:"):
                sender = line.split(":", 1)[1].strip()
        body_lines = lines
    except Exception:
        body_lines = []
    body_text = "\n".join(body_lines)
    iocs = extract_iocs(body_text)
    sender_domain = sender.split("@")[1].strip() if "@" in sender else ""
    headers = {"file": os.path.basename(path)}
    return {
        "subject": subject,
        "from": sender,
        "sender_domain": sender_domain,
        "received_ips": iocs['ips'],
        "body_text": body_text,
        "urls": iocs['urls'],
        "domains": iocs['domains'],
        "headers": headers
    }

def defang_url(u: str) -> str:
    return u.replace("http", "hxxp").replace(".", "[.]")

def defang_ip(ip: str) -> str:
    return ip.replace(".", "[.]")

def defang_domain(d: str) -> str:
    return d.replace(".", "[.]")

def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def vt_url_id(url: str) -> str:
    # VT spec: base64-url-safe of the original URL, without padding
    b64 = base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8')
    return b64.strip('=')

def get_keywords(category: str) -> List[str]:
    """Fetch all keywords for a given category from DB."""
    return [k.value.lower() for k in Keyword.query.filter_by(category=category).all()]

def heuristic_flags_from_email(subject: str, sender: str, body: str, urls: List[str], headers_json: str) -> List[str]:
    flags: List[str] = []
    text = (subject + " " + body).lower()

    # 🔑 Fetch keywords dynamically from DB instead of hardcoding
    urgent_keywords = get_keywords("urgency")
    cred_keywords   = get_keywords("credential_request")

    if any(k in text for k in urgent_keywords):
        flags.append("urgent_language")
    if any(k in text for k in cred_keywords):
        flags.append("credential_harvest")

    # Obfuscated URL check (unchanged)
    if any(("hxxp" in (u or "").lower()) or ("[.]" in (u or "")) or ("%2e" in (u or "").lower()) for u in urls or []):
        flags.append("obfuscated_url")

    # Domain mismatch check (unchanged)
    sender_domain = sender.split("@")[1].lower().strip() if "@" in sender else ""
    url_domains = []
    for u in urls or []:
        m = re.search(r'https?://([^/\s]+)', u)
        if m:
            url_domains.append(m.group(1).lower())
    if sender_domain and url_domains and not any(sender_domain in d or d.endswith(sender_domain) for d in url_domains):
        flags.append("domain_mismatch")

    # SPF/DKIM checks (unchanged)
    try:
        headers = json.loads(headers_json or "{}")
    except Exception:
        headers = {}
    spf = str(headers.get("spf_result", "")).lower()
    dkim = str(headers.get("dkim_result", "")).lower()
    if spf in ("fail", "softfail"):
        flags.append("spf_fail")
    if dkim == "fail":
        flags.append("dkim_fail")

    return flags

def heuristic_hard_verdict(flags: List[str]) -> Optional[str]:
    strong = {"credential_harvest", "domain_mismatch", "spf_fail", "dkim_fail"}
    count_strong = sum(1 for f in flags if f in strong)
    if count_strong >= 2:
        return "phishing"
    if "urgent_language" in flags and "obfuscated_url" in flags:
        return "phishing"
    if len(flags) >= 3:
        return "suspicious"
    return None

def normalize_vt(malicious_counts: List[int], k: float = 3.0) -> float:
    vt_sum = sum(malicious_counts)
    return 1.0 - math.exp(-(vt_sum / k))

def normalize_otx(pulses_total: int) -> float:
    return min(1.0, pulses_total / 5.0)

def normalize_abuse(max_score: int) -> float:
    return max(0.0, min(1.0, max_score / 100.0))

def normalize_heuristic(flags: List[str]) -> float:
    weights = {
        "spf_fail": 0.25, "dkim_fail": 0.25, "domain_mismatch": 0.25,
        "urgent_language": 0.15, "credential_harvest": 0.20, "obfuscated_url": 0.15
    }
    total = sum(weights.get(f, 0.1) for f in flags)
    return min(1.0, total)

def combine_ti_nlp(nlp_score: float, nlp_label: str,
                   vt_mal_counts: List[int],
                   otx_pulses_total: int,
                   abuse_max_score: int,
                   heuristic_flags: List[str]) -> dict:
    override = heuristic_hard_verdict(heuristic_flags)
    w = {"nlp": 0.35, "vt": 0.25, "otx": 0.15, "abuse": 0.15, "heur": 0.10}
    if nlp_label == "phishing":
        risk_nlp = float(nlp_score)
    elif nlp_label == "clean":
        risk_nlp = float(1.0 - nlp_score)
    else:
        risk_nlp = float(max(0.4, nlp_score))
    risk_vt = float(normalize_vt(vt_mal_counts))
    risk_otx = float(normalize_otx(otx_pulses_total))
    risk_abuse = float(normalize_abuse(abuse_max_score))
    risk_heur = float(normalize_heuristic(heuristic_flags))
    risk_final = (w["nlp"]*risk_nlp + w["vt"]*risk_vt + w["otx"]*risk_otx + w["abuse"]*risk_abuse + w["heur"]*risk_heur)
    signals_list = [risk_nlp, risk_vt, risk_otx, risk_abuse, risk_heur]
    confidence = 0.5 + 0.5 * (max(signals_list) - min(signals_list))
    if override:
        verdict = override
    else:
        verdict = "phishing" if risk_final >= 0.7 else ("suspicious" if risk_final >= 0.4 else "clean")
    return {
        "verdict": verdict,
        "risk_final": round(risk_final, 4),
        "confidence": round(confidence, 4),
        "signals": {
            "nlp": {"risk": round(risk_nlp, 4), "score": round(float(nlp_score), 4), "label": nlp_label},
            "vt": {"risk": round(risk_vt, 4), "malicious_total": int(sum(vt_mal_counts)), "ioc_count": int(len(vt_mal_counts))},
            "otx": {"risk": round(risk_otx, 4), "pulses_total": int(otx_pulses_total)},
            "abuseipdb": {"risk": round(risk_abuse, 4), "max_score": int(abuse_max_score)},
            "heuristic": {"risk": round(risk_heur, 4), "flags": list(heuristic_flags)},
        }
    }
