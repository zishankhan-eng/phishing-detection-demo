# Phishing Attack Simulation and Detection System

A beginner-friendly Python cybersecurity mini-project for email/URL risk awareness.

## Features
- Rule-based email text analysis
- URL checks: non-HTTPS, URL shorteners, IP-address hosts, punycode, unusual domain/path patterns
- Risk score from 0 to 100 with Low / Medium / High labels
- Safe training sample and awareness quiz
- Local-only web interface; no emails are sent and no passwords/OTPs are collected

## Requirements
- Python 3.8 or newer
- No third-party packages required

## Run
1. Extract the ZIP file.
2. Open a terminal in the project folder.
3. Run: `python app.py`
4. Open `http://127.0.0.1:8000` in your browser.
5. Stop the server with `Ctrl+C`.

## Project structure
- `app.py` — local HTTP server and detection logic
- `index.html` — user interface, training sample and awareness quiz

## How it works
The scanner searches for common urgency and credential-request phrases, extracts URLs, and checks selected URL characteristics. It adds heuristic risk points and assigns a risk category. The rules are intentionally simple so students can understand and explain them.

## Limitations
This is a learning prototype, not a production security gateway. It does not check domain reputation, DNS, TLS certificates, sender authentication (SPF/DKIM/DMARC), attachments, or machine-learning models. False positives and false negatives are possible. A low score does not guarantee safety.

## Safe-use note
Use only sample messages or emails you are authorised to analyse. This project does not send phishing messages, clone websites, or capture credentials.
