# 🚀 CORS Hunter

**CORS Hunter** is a lightweight, zero-dependency Python tool designed to detect Cross-Origin Resource Sharing (CORS) misconfigurations. It automates the testing methodology of various origin-spoofing techniques to identify overly permissive CORS policies.

*Author: [MARKAM](https://github.com/markamsecurity)*

---

## 📖 Description

This tool is a Python rewrite of `cors_check.sh`. It systematically probes target endpoints using various `Origin` header manipulations to check if a server reflects origins while allowing credentials. 

Unlike basic CORS scanners, `cors_hunter.py` includes built-in **consistency checks**. By sending random, unrelated origins alongside known bypass vectors, it can automatically differentiate between a genuinely misconfigured allow-list (like a vulnerable regex) and a server that simply reflects *any* origin unconditionally.

## ✨ Features

*   **Zero Dependencies:** Built entirely with the Python standard library. No `pip install` required.
*   **Comprehensive Test Vectors:**
    *   Arbitrary origin reflection
    *   Null origin (`null`)
    *   Subdomain trust abuse
    *   Suffix/Prefix confusion
    *   Protocol downgrade (HTTP vs HTTPS)
    *   Trailing dot and case variations
*   **Automated Consistency Checking:** Automatically detects unconditional reflection versus exploitable regex flaws.
*   **Flexible Output:** Generates JSON lines and human-readable text reports. Supports outputting to a single aggregated file or a structured directory per target.
*   **Rate Limiting:** Built-in request delays to ensure polite and stable scanning.

## 🚀 Installation

Since it uses only the standard library, you just need to download the script and make it executable. Requires **Python 3**.

```bash
git clone https://github.com/markamsecurity/cors-hunter.git
cd cors-hunter
chmod +x cors_hunter.py
