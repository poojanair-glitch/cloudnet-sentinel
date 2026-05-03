from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    role_arn = db.Column(db.String(255), nullable=False)
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(50))
    exposure = db.Column(db.Integer)
    report_data = db.Column(db.Text) # Stores full JSON for history loading
