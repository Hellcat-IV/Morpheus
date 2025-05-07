# File: head.py
# Updated: 07th May 2025
# Sentinel is a python tool to check for common vulnerabilities
# Version 1.0.0

# Reference: 
# - https://github.com/dustyfresh/PHP-vulnerability-audit-cheatsheet?tab=readme-ov-file

vuln_patterns = {
    "XSS": [
        r"echo\s+.*?\$_(GET|POST|REQUEST|SERVER|COOKIE)\b",
        r"print\s+.*?\$_(GET|POST|REQUEST|SERVER|COOKIE)\b"
    ],
    "Command Execution": [
        r"\b(shell_exec|system|exec|popen|passthru|proc_open|pcntl_exec)\s*\(\s*(?![^\)]*[\$_(GET|POST|REQUEST|COOKIE|SERVER)|\$[a-zA-Z_][a-zA-Z0-9_]*])"
    ],
    "Code Execution": [
        r"\b(eval|assert|create_function)\s*\(\s*(?![^\)]*[\$_(GET|POST|REQUEST|COOKIE|SERVER)|\$[a-zA-Z_][a-zA-Z0-9_]*])",
        r"preg_replace\s*\(.*?/e.*?\)(?!.*[\$_(GET|POST|REQUEST|COOKIE|SERVER)|\$[a-zA-Z_][a-zA-Z0-9_]*])"
    ],
    "Secrets Detection": [
        # AWS, Azure, GCP
        r"\b[A-Za-z0-9]{20,}=[A-Za-z0-9/+=]{40,}",  # Exemple : Basic API Key
        r"\bAKIA[A-Za-z0-9]{16}\b",  # Exemple : AWS Access Key ID
        r"\bAIza[A-Za-z0-9_-]{35}\b",  # Exemple : Google API Key
        r"\bsk_test_[0-9a-zA-Z]{24}\b",  # Exemple : Stripe Secret Key (test)
        # OAuth
        r"\b[0-9a-f]{32}\b",
        # JWT
        r"\b[0-9a-zA-Z_-]{32,}\.[0-9a-zA-Z_-]{32,}\.[0-9a-zA-Z_-]{32,}\b",  # Exemple : JWT Token
        # HMAC
        r"\b[0-9a-fA-F]{64}\b"  # HMAC/SHA-256 secrète
    ],
    "SQL Injection": [
        r"\$sql\s*=.*?\$_(GET|POST|REQUEST|COOKIE)\b.*?;",
        r"(mysqli_query|mysql_query|pg_query)\s*\(.*?\$_(GET|POST|REQUEST|COOKIE|SERVER)\b",
        r"\$db->query\s*\(.*?\$_(GET|POST|REQUEST|COOKIE)\b",
        r"(?i)(SELECT|INSERT|UPDATE|DELETE).*?%.*?[\"']",
        r"(?i)(?:=|\.=)\s*['\"].*\b(SELECT|INSERT|UPDATE|DELETE|REPLACE|FROM|WHERE|LIKE|ORDER\s+BY|GROUP\s+BY)\b.*['$%]",
    ],
    "Information Leak": [
        r"\bphpinfo\s*\("
    ],
    "Debug/Dev Mode": [
        r"\$_GET\s*\[\s*['\"](debug|test)['\"]\s*\]",
        r"\bvar_dump\s*\(",
        r"\bprint_r\s*\("
    ],
    "RFI/LFI": [
        # Dynamic inputs
        r"(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\b",
        r"(include|require|include_once|require_once)\s*\(\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*\)",
    ],
    "Misc": [
        r"header\s*\(\s*['\"]Location.*?\$_(GET|POST|REQUEST|SERVER)\b",
        r"\$_SERVER\s*\[\s*['\"]HTTP_USER_AGENT['\"]\s*\]"
    ],
    "Path Traversal": [
        r"file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\b"
    ]
}
