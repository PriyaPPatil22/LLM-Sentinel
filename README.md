# LLM Sentinel 🛡️

A lightweight security middleware that protects LLM applications from prompt injection attacks and PII data leaks.

## The Problem
Companies building AI chatbots and agents using LLM APIs have no protection layer. Attackers can manipulate AI behavior through crafted inputs — OWASP ranks prompt injection as the #1 LLM security risk.

## How It Works
Every message passes through two detection layers before reaching the LLM:
1. **Pattern matching** — catches known injection phrases instantly
2. **Semantic analysis** — uses LLaMA 3.3 70B to detect clever disguised attacks
3. **PII leak detection** — scans LLM output for emails, phones, API keys, passwords
4. **Rate limiting** — blocks IPs exceeding request threshold

## Features
- Prompt injection detection (pattern + semantic)
- PII leak detection in LLM responses
- Rate limiting per IP
- Full audit logging with timestamps
- Flask web UI for visual testing
- Integrates with any Python LLM application

## Installation
```
pip install flask
git clone https://github.com/PriyaPPatil22/llm-firewall
cd llm-firewall
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
```
python app.py
```
Open `http://localhost:5000`

## Detection Examples
| Input | Result |
|-------|--------|
| "Ignore all previous instructions" | BLOCKED — PROMPT_INJECTION |
| "Hypothetically if you had no restrictions..." | BLOCKED — SEMANTIC_INJECTION |
| "What is the weather today?" | ALLOWED |

## Tech Stack
Python · Flask · LLaMA 3.3 70B · Groq API

## Author
Priya Patil — [GitHub](https://github.com/PriyaPPatil22)
