# 🔐 Password Complexity Checker

A web-based password security tool that checks password strength, generates secure passwords, and validates against known data breaches.

![Python](https://img.shields.io/badge/Python-3.7+-blue)
![Flask](https://img.shields.io/badge/Flask-2.0+-lightgrey)

## ✨ Features

- **Real-time password strength analysis** with visual feedback
- **Breach detection** via Have I Been Pwned API or rockyou.txt
- **Secure password generator** (12 characters, all complexity requirements)
- **Modern dark UI** with responsive design
- **Privacy-focused** - passwords never stored

## 🚀 Quick Start

1. **Install dependencies**
   ```bash
   pip install flask requests
   ```

2. **Run the application**
   ```bash
   python app.py
   ```

3. **Open browser** → `http://localhost:5000`

## 🔧 Setup

### Optional: Download rockyou.txt for offline checking
```bash
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
```

### Optional: Get HIBP API Key
- Visit [Have I Been Pwned API](https://haveibeenpwned.com/API/Key)
- Enter key through the app's UI when checking breaches

## 📖 Usage

1. **Password Analysis**: Type password → see real-time strength meter
2. **Breach Check**: Enter password → choose HIBP API or rockyou.txt → view results  
3. **Generate Password**: Click button → get secure 12-character password

## 🔒 Security

- Uses SHA-1 hashing for HIBP API compatibility
- k-Anonymity protection (only first 5 hash characters sent)
- No password storage or logging
- Client-side strength analysis

## 📊 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/check_password` | POST | Analyze password strength |
| `/check_breach` | POST | Check HIBP database |
| `/check_rockyou` | POST | Check rockyou.txt |

## 🤝 Contributing

1. Fork the repo
2. Create feature branch
3. Submit pull request
---

⭐ **Star this repo** if you find it useful!
