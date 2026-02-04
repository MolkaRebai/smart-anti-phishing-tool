# Smart Anti-Phishing Tool 🛡️

![License](https://img.shields.io/github/license/MolkaRebai/smart-anti-phishing-tool)
![Issues](https://img.shields.io/github/issues/MolkaRebai/smart-anti-phishing-tool)
![Stars](https://img.shields.io/github/stars/MolkaRebai/smart-anti-phishing-tool)
![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)

An intelligent, real-time security solution designed to detect and block phishing attempts using advanced URL analysis and machine learning heuristics.

## 🚀 Overview

The **Smart Anti-Phishing Tool** helps users identify malicious URLs and suspicious web content before they fall victim to social engineering attacks. By analyzing various features—including URL length, domain age, SSL presence, and content patterns—the tool provides a safety score for any given link.

### Key Features
- **🔍 Real-time URL Scanning:** Instantly check URLs for known phishing patterns.
- **🧠 ML-Powered Detection:** Uses a trained model to identify "zero-day" phishing sites that aren't on blacklists yet.
- **📊 Feature Extraction:** Analyzes 30+ parameters including obfuscation, redirection, and domain impersonation.
- **🛡️ Risk Assessment:** Provides a clear "Safe," "Suspicious," or "Malicious" verdict.

## 🛠️ Tech Stack

- **Language:** Python 3.x
- **Libraries:** Pandas, Scikit-Learn, BeautifulSoup4, Requests
- **Backend/API (Optional):** Flask / FastAPI
- **Data Source:** Trained on datasets from PhishTank and OpenPhish.

## ⚙️ Installation

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/MolkaRebai/smart-anti-phishing-tool.git](https://github.com/MolkaRebai/smart-anti-phishing-tool.git)
   cd smart-anti-phishing-tool
