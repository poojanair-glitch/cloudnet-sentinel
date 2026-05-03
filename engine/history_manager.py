import sqlite3
import datetime
import os

class HistoryManager:
    def __init__(self, db_path='data/sentinel.db'):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    region TEXT,
                    risk_score REAL,
                    severity TEXT,
                    path_count INTEGER,
                    account_id TEXT
                )
            ''')

    def log_scan(self, region, risk_score, severity, path_count, account_id="unknown"):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO scan_history (timestamp, region, risk_score, severity, path_count, account_id)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (datetime.datetime.now().isoformat(), region, risk_score, severity, path_count, account_id))

    def get_latest_score(self, region):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT risk_score FROM scan_history 
                WHERE region = ? 
                ORDER BY timestamp DESC LIMIT 1
            ''', (region,))
            row = cursor.fetchone()
            return row[0] if row else None
