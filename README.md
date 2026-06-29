# 🛡️ Python Log Analyzer & Threat Detection System

## 📌 Overview

A Python-based Security Operations Center (SOC) project that analyzes log files and detects suspicious activities such as brute-force attacks, PowerShell execution, ransomware indicators, user creation, IOC matches, and Windows Event IDs.

---

## 🚀 Features

- Brute Force Detection
- PowerShell Detection
- User Creation Detection
- Ransomware Detection
- IOC Detection
- Windows Event Detection
- MITRE ATT&CK Mapping
- CSV Report Generation
- PDF Incident Report
- Streamlit Dashboard

---

## 🛠️ Technologies Used

- Python
- Streamlit
- Matplotlib
- ReportLab

---

## 📂 Project Structure

```text
Python-Log-Analyzer/
│
├── analyzer.py
├── dashboard.py
├── detector.py
├── parser.py
├── report.py
├── mitre.py
├── rules.py
├── requirements.txt
├── README.md
│
├── logs/
├── reports/
├── ioc/
└── screenshots/
```

---

## ⚙️ Installation

```bash
git clone <repository-url>
cd Python-Log-Analyzer
pip install -r requirements.txt
```

---

## ▶️ Run the Dashboard

```bash
streamlit run dashboard.py
```

---

## 📄 Reports

- CSV Report
- PDF Incident Report

---

## 🛡️ MITRE ATT&CK Techniques

| Attack | Technique |
|---------|-----------|
| Brute Force | T1110 |
| PowerShell | T1059.001 |
| User Creation | T1136 |
| Ransomware | T1486 |

---

## 👨‍💻 Author

**Shiv Kumar Maurya**

Cybersecurity Enthusiast | SOC Analyst Aspirant