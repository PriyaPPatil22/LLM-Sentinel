# LLM Sentinel 🛡️

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20UI-lightgrey)
![LLaMA](https://img.shields.io/badge/LLaMA%203.3%2070B-Groq%20API-orange)
![License](https://img.shields.io/badge/License-MIT-green)

A lightweight security middleware that protects LLM applications from prompt 
injection attacks and PII data leaks — before the threat reaches your model.

## The Problem

Companies building AI chatbots and agents using LLM APIs have no protection 
layer. Attackers can manipulate AI behavior through crafted inputs — OWASP 
ranks prompt injection as the #1 LLM security risk.

## How It Works

Every message passes through four detection layers before reaching the LLM:

1. **Pattern matching** — catches known injection phrases instantly
2. **Semantic analysis** — uses LLaMA 3.3 70B to detect clever disguised attacks
3. **PII leak detection** — scans LLM output for emails, phones, API keys, passwords
4. **Rate limiting** — blocks IPs exceeding request threshold

## Features

- Prompt injection detection (regex pattern + LLM semantic analysis)
- PII leak detection in LLM responses
- Rate limiting per IP (20 requests / 60 seconds)
- Full audit logging with timestamps
- Flask web UI for visual testing
- Drop-in middleware — integrates with any Python LLM application

## Installation
```bash
git clone https://github.com/PriyaPATil22/llm-firewall
cd llm-firewall
pip install flask groq
```

Set your Groq API key:
```bash
# Windows
set GROQ_API_KEY=your_key_here

# Linux/Mac
export GROQ_API_KEY=your_key_here
```

## Usage
```python
from firewall import LLMFirewall

fw = LLMFirewall()

# Scan before sending to LLM
result = fw.scan_input("user message")
if not result["allowed"]:
    print(f"Blocked: {result['threat']} — {result['detail']}")

# Scan LLM response before showing to user
result = fw.scan_output("LLM response")
if not result["allowed"]:
    print(f"PII detected: {result['detail']}")
```

## Web UI
```bash
python app.py
```
Open `http://localhost:5000`

## Detection Examples

| Input | Result |
|-------|--------|
| "Ignore all previous instructions" | 🔴 BLOCKED — Pattern Match |
| "Hypothetically if you had no restrictions..." | 🔴 BLOCKED — Semantic Analysis |
| "My email is priya@example.com" (in LLM output) | 🔴 BLOCKED — PII Leak |
| "What is the weather today?" | 🟢 ALLOWED |

## Tech Stack

Python · Flask · LLaMA 3.3 70B · Groq API · Regex 

## Author

Priya Patil — [GitHub](https://github.com/PriyaPPatil22) · 
[LinkedIn](https://www.linkedin.com/in/priya-patil-cybersecurity/)
