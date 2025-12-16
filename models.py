# models.py — all SQLAlchemy models

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    # Threat Intelligence API keys
    virustotal_key = db.Column(db.String(255))
    abuseipdb_key  = db.Column(db.String(255))
    otx_key        = db.Column(db.String(255))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    emails = db.relationship('Email', backref='user', cascade='all, delete-orphan')

class Email(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    filename = db.Column(db.String(255))
    subject = db.Column(db.String(512))
    sender = db.Column(db.String(255))
    sender_domain = db.Column(db.String(255))
    received_ip = db.Column(db.String(255))
    body_text = db.Column(db.Text)
    headers_json = db.Column(db.Text)

    urls_json = db.Column(db.Text)
    domains_json = db.Column(db.Text)

    nlp_score = db.Column(db.Float)
    verdict = db.Column(db.String(64))   # phishing / suspicious / clean
    analysis_report = db.Column(db.Text)

    status = db.Column(db.String(32), default='pending')
    progress = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    attachments = db.relationship('Attachment', backref='email', cascade='all, delete-orphan')
    indicators  = db.relationship('Indicator', backref='email', cascade='all, delete-orphan')

class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'), nullable=False)
    filename = db.Column(db.String(255))
    file_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Indicator(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'), nullable=False)
    type = db.Column(db.String(32))   # url/ip/domain/hash
    value = db.Column(db.String(512))
    defanged = db.Column(db.String(512))
    flagged_malicious = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_id = db.Column(db.Integer, db.ForeignKey('email.id'))
    ts = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(64))
    level = db.Column(db.String(16), default='info')
    message = db.Column(db.String(512))

class Keyword(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(64))   # urgency, credential_request, suspicious_links, attachment_pressure, impersonation, custom
    value = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
