# 💎 CloudNet Sentinel v1

**CloudNet Sentinel** is a DevSecOps-ready cloud security system that models AWS infrastructure as a graph to detect real attack paths and prioritize them using security and financial impact intelligence.

---

## 🚀 Features
- **Graph-Based Analysis**: Uses `networkx` to build a real relationship graph of AWS assets.
- **Attack Path Detection**: Detects External Access, Privilege Escalation, and Data Exfiltration paths.
- **Risk Scoring**: Prioritizes findings with a 0-100 risk score.
- **Cost Impact**: Estimates the monthly financial exposure of insecure assets.
- **Dual Interface**: Modern Flask-based dashboard and powerful CLI.

---

## 🏗️ Architecture
```
Browser (Flask UI)
        ↓
Flask App (UI Layer)
        ↓
Core Engine (Python)
 ├── Scanner (boto3)
 ├── Graph Builder (networkx)
 ├── Attack Path Engine (Traversals)
 ├── Risk Engine (Scoring)
 └── Cost Engine (Impact)
        ↓
AWS Infrastructure
```

---

## 🛠️ Setup & Installation

### 1. Prerequisites
- Python 3.8+
- AWS CLI configured with read-only permissions (`aws configure`)

### 2. Install Dependencies
```bash
cd cloudnet-sentinel
pip install -r requirements.txt
```

### 3. Usage

#### **Run as CLI**
```bash
python main.py --region us-east-1
```

#### **Run as Flask Web App**
```bash
python app.py
```
Open your browser at `http://localhost:5001`.

---
This is a code bundle for CloudNet Sentinel Dashboard. The original project is available at https://cloudnet-sentinel.onrender.com

## 📊 Sample Findings
🚨 **ATTACK PATH DETECTED**
- **Type**: Data Exfiltration
- **Path**: `Internet -> i-0abcd1234 -> iam-role-admin -> s3-bucket-confidential`
- **Risk**: CRITICAL (92/100)
- **Financial Impact**: ₹3,000/month + exploitation risk

---

## 🔒 Security Note
This tool uses your local AWS credentials (`~/.aws/credentials`). It does **not** store or transmit keys. For best results, use a ReadOnlyAccess IAM user.

---

**Developed by CloudNet Sentinel Team**
