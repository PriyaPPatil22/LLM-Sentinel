from scanner import check_injection, check_pii_leak, check_semantic
from collections import defaultdict
from datetime import datetime
import time
import json

class LLMFirewall:
    def __init__(self, block_injections=True, block_pii=True, log=True, rate_limit=5, rate_window=60):
        self.block_injections = block_injections
        self.block_pii = block_pii
        self.log = log
        self.audit_log = []
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.ip_attempts = defaultdict(list)

    def check_rate_limit(self, ip):
        now = time.time()
        self.ip_attempts[ip] = [t for t in self.ip_attempts[ip] if now - t < self.rate_window]
        self.ip_attempts[ip].append(now)
        return len(self.ip_attempts[ip]) > self.rate_limit

    def scan_input(self, user_message, ip="unknown"):
        result = {
            "allowed": True,
            "threat": None,
            "detail": None,
            "original": user_message,
            "timestamp": datetime.now().isoformat()
        }

        if self.check_rate_limit(ip):
            result["allowed"] = False
            result["threat"] = "RATE_LIMIT"
            result["detail"] = f"Too many requests from {ip}"
            if self.log:
                self.audit_log.append(result)
            return result

        if self.block_injections:
            flagged, pattern = check_injection(user_message)
            if flagged:
                result["allowed"] = False
                result["threat"] = "PROMPT_INJECTION"
                result["detail"] = f"Matched pattern: {pattern}"

            if result["allowed"]:
                semantic = check_semantic(user_message)
                if semantic["is_injection"] and semantic["confidence"] >= 85:
                    result["allowed"] = False
                    result["threat"] = "SEMANTIC_INJECTION"
                    result["detail"] = semantic["reason"]
                    result["confidence"] = semantic["confidence"]

        if self.log:
            self.audit_log.append(result)

        return result

    def scan_output(self, llm_response):
        result = {
            "allowed": True,
            "threat": None,
            "detail": None,
            "timestamp": datetime.now().isoformat()
        }

        if self.block_pii:
            flagged, match = check_pii_leak(llm_response)
            if flagged:
                result["allowed"] = False
                result["threat"] = "PII_LEAK"
                result["detail"] = f"Detected: {match}"

        if self.log:
            self.audit_log.append(result)

        return result

    def get_logs(self):
        return json.dumps(self.audit_log, indent=2)