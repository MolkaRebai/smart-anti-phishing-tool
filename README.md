# Smart Anti-Phishing Tool

A Chrome extension (Manifest V3) that classifies URLs in real time 
as **benign, phishing, malware, or defacement** using a LightGBM 
model running entirely client-side — no external API, no latency, 
no data leaving the browser.

---

## How it works
```
Chrome MV3 service worker intercepts navigation
        │
        ▼
21 NLP features extracted from URL (JavaScript)
        │
        ▼
LightGBM classifier runs locally (model_info.json)
        │
        ▼
4-class prediction + confidence score
        │
        ├── Malicious (>85% confidence) → block page redirect
        ├── Suspicious → inline warning on all page links
        └── Benign → no action
```

---

## Model Performance

Trained on **651,191 labeled URLs** across 4 classes.  
Evaluated on 130,239 test samples.

| Class | Precision | Recall | F1-Score |
|------------|-----------|--------|----------|
| Benign | 0.96 | 0.99 | 0.97 |
| Defacement | 0.93 | 0.98 | 0.96 |
| Malware | 0.96 | 0.84 | 0.89 |
| Phishing | 0.90 | 0.79 | 0.84 |
| **Overall** | **0.95** | **0.95** | **0.95** |

> Full training pipeline and evaluation in `model/training.ipynb`

---

## Features extracted per URL (21 total)

| Feature | Description |
|---------|-------------|
| `ip_exist` | IP address used instead of domain name |
| `abnormal_url` | Hostname not found within the URL |
| `dot_count` | Number of dots (subdomain depth indicator) |
| `www_count` | Number of www occurrences |
| `@_count` | @ symbol presence (hides real destination) |
| `hyphen_count` | Hyphens in domain (impersonation indicator) |
| `subdomain_count` | Number of subdomains |
| `shortening_service` | Known URL shortener detected |
| `https_count` | HTTPS occurrence count |
| `http_count` | HTTP occurrence count |
| `percent_count` | % encoding (obfuscation indicator) |
| `query_count` | Number of query parameters |
| `equal_count` | Number of = signs in URL |
| `url_length` | Total URL length |
| `hostname_length` | Length of hostname |
| `no_embed` | Double slash in path (embed indicator) |
| `suspicious_words` | Phishing keywords (login, verify, secure...) |
| `digit_count` | Number of digits in URL |
| `letters_count` | Number of letters in URL |
| `fd_length` | Length of first directory in path |
| `tld_length` | Length of top-level domain |

## Project Structure
```
smart-anti-phishing-tool/
├── blocked/
│   └── blocked.html
├── icons/
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
├── model/
│   ├── training.ipynb
│   ├── convert_model.ipynb
│   └── model_info.json
├── popup/
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
├── background.js
├── content.js
├── manifest.json
├── download_dataset.py
├── download_kaggle.py
└── README.md
```

## Installation

1. Clone the repo
2. Open Chrome → `chrome://extensions`
3. Enable **Developer Mode**
4. Click **Load unpacked** → select repo folder
5. Visit any website — URLs are classified automatically

No server setup required. The model runs entirely in your browser.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| ML Model | LightGBM (multiclass) |
| Feature Engineering | NLP, URL parsing, regex |
| Model Export | JSON weight serialization |
| Extension | JavaScript, Chrome Manifest V3 |
| Training | Python, Scikit-Learn, Pandas |

---

## Design decisions

**Client-side inference** — running the model in the browser means 
zero latency, offline support, and no URL data sent to external servers. 
URLs are private by design.

**4-class classification** — distinguishing between phishing, malware, 
and defacement provides more actionable alerts than binary detection.

**MV3 service worker** — built on the current Chrome extension standard, 
ensuring long-term compatibility.
