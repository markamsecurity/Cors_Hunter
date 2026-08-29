#!/usr/bin/env python3
"""
cors_hunter.py — CORS misconfiguration testing tool (Python rewrite of cors_check.sh)

Same testing methodology as the cors-hunter skill (arbitrary reflection, null origin,
subdomain/prefix/suffix bypass, protocol downgrade, case variation) plus two built-in
"consistency check" vectors (random unrelated origins) so unconditional reflection is
detected automatically instead of needing a manual retest pass.

Pure stdlib — no pip install required.

Usage:
  ./cors_hunter.py -u https://target.com/api/endpoint
  ./cors_hunter.py -u https://target.com/api/endpoint -c "session=abc123" -t target.com -r 1.5
  ./cors_hunter.py -l endpoints.txt -o results/

Output: JSON + human-readable txt per target, plus a live colored summary.
This surfaces CANDIDATES only — severity/credential-scope/browser-truth verification
from cors-hunter.md still applies before anything is reported.
"""
import time

def show_banner():
    print("""
=================================================
|    🚀CORS MISCONFIGURATION CHECKER             |
=================================================
  * Author  : MARKAM
  * Github  :https://github.com/markamsecurity 
=================================================
    """)

show_banner()
print("Initializing modules...")
time.sleep(1)

import argparse
import json
import os
import random
import string
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

UA = "Mozilla/5.0 (compatible; cors-hunter/2.0; authorized-testing)"


class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def colorize(text, color):
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{C.END}"


def random_string(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def build_origin_vectors(base_domain):
    r1, r2, r3 = random_string(), random_string(), random_string()
    return [
        ("arbitrary-reflection", f"https://evil-{r1}.example"),
        ("null-origin", "null"),
        ("subdomain-trust-abuse", f"https://evil-{r1}.{base_domain}"),
        ("suffix-confusion", f"https://{base_domain}.evil-{r1}.example"),
        ("prefix-confusion", f"https://evil{base_domain}"),
        ("suffix-append", f"https://{base_domain}evil-{r1}.example"),
        ("protocol-downgrade", f"http://{base_domain}"),
        ("trailing-dot", f"https://{base_domain}."),
        ("case-variation", f"https://{base_domain.upper()}"),
        # Automated consistency check: if these random, unrelated origins also get
        # reflected, that proves unconditional reflection rather than a real allow-list.
        ("consistency-check-1", f"https://random-{r2}.example"),
        ("consistency-check-2", f"https://random-{r3}.example"),
    ]


def normalize_headers(headers):
    if not headers:
        return {}
    return {k.lower(): v for k, v in headers.items()}


def send_request(url, origin, cookie=None, method="GET", timeout=15):
    headers = {"User-Agent": UA, "Origin": origin}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, normalize_headers(resp.headers), None
    except urllib.error.HTTPError as e:
        return e.code, normalize_headers(e.headers), None
    except (urllib.error.URLError, TimeoutError) as e:
        return None, {}, str(e)


def test_preflight(url, origin, cookie=None):
    headers = {"User-Agent": UA, "Origin": origin, "Access-Control-Request-Method": "GET"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, headers=headers, method="OPTIONS")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return normalize_headers(resp.headers)
    except urllib.error.HTTPError as e:
        return normalize_headers(e.headers)
    except Exception:
        return {}


def analyze(origin, headers):
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials")
    vary = headers.get("vary", "") or ""
    reflects_exact = acao is not None and acao == origin
    creds_true = acac is not None and acac.strip().lower() == "true"
    return {
        "acao": acao,
        "acac": acac,
        "vary_origin": "origin" in vary.lower(),
        "reflects_exact": reflects_exact,
        "creds_true": creds_true,
    }


def classify(vector_name, analysis):
    """Same false-positive checklist as cors-hunter.md, applied in code."""
    if analysis["acao"] == "*" and not analysis["creds_true"]:
        return "info", "Wildcard ACAO without credentials — not exploitable by design"
    if analysis["acao"] == "*" and analysis["creds_true"]:
        return "info", "Wildcard ACAO + credentials=true — invalid per Fetch spec, browsers reject this combo"
    if analysis["reflects_exact"] and analysis["creds_true"]:
        if vector_name == "null-origin":
            return "candidate", "Null origin accepted WITH credentials=true — high-confidence finding"
        if "consistency-check" in vector_name:
            return "candidate", "Unrelated random origin reflected WITH credentials=true — unconditional reflection confirmed"
        return "candidate", "Origin reflected WITH credentials=true — check consistency-check vectors below to confirm it isn't a real allow-list entry"
    if analysis["reflects_exact"] and not analysis["creds_true"]:
        return "info", "Origin reflected but no credentials flag — low impact, note only"
    if vector_name == "null-origin" and analysis["acao"] == "null":
        return "candidate", "Literal 'null' accepted as ACAO value"
    return "none", "No notable behavior"


def run(url, cookie, base_domain, rate):
    vectors = build_origin_vectors(base_domain)
    results = []
    print(colorize(f"\n[*] Target: {url}", C.CYAN))
    print(colorize(f"[*] {len(vectors)} origin vectors (rate: {rate}s/request)\n", C.CYAN))

    for name, origin in vectors:
        status, headers, err = send_request(url, origin, cookie)
        if not headers:
            headers = test_preflight(url, origin, cookie)
        analysis = analyze(origin, headers)
        severity, note = classify(name, analysis)

        results.append({
            "vector": name,
            "origin_sent": origin,
            "status": status,
            "error": err,
            "acao": analysis["acao"],
            "acac": analysis["acac"],
            "vary_includes_origin": analysis["vary_origin"],
            "severity": severity,
            "note": note,
        })

        tag = {
            "candidate": colorize("[CANDIDATE]", C.RED),
            "info": colorize("[INFO]     ", C.YELLOW),
            "none": colorize("[ok]       ", C.GREEN),
        }[severity]
        print(f"{tag} {name:<24} Origin: {origin[:45]:<45} ACAO={analysis['acao']} ACAC={analysis['acac']}")
        if severity == "candidate":
            print(colorize(f"             -> {note}", C.RED))

        time.sleep(rate)

    return results


def write_outputs(url, results, outpath, single_file_mode, first_write):
    """
    Two modes:
      - single_file_mode=True:  outpath IS the exact output file (e.g. "find_cors.txt").
                                 Each target's results are appended to this one file
                                 (with a separator), plus one sibling JSONL file
                                 (same name, .jsonl extension) with one JSON object
                                 per line — one line per scanned target.
      - single_file_mode=False: outpath is treated as a directory (old behavior),
                                 one <domain>_cors_results.{json,txt} pair per target.
    """
    report = {
        "target": url,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "candidates": [r for r in results if r["severity"] == "candidate"],
    }

    if single_file_mode:
        parent = os.path.dirname(outpath)
        if parent:
            os.makedirs(parent, exist_ok=True)
        if os.path.isdir(outpath):
            sys.exit(
                f"[!] Error: '{outpath}' already exists as a directory, not a file.\n"
                f"    Choose a different -o name, or delete/rename that directory first."
            )

        base, _ = os.path.splitext(outpath)
        jsonl_path = f"{base}.jsonl"
        mode = "w" if first_write else "a"

        with open(outpath, mode) as f:
            f.write(f"CORS Test Results -- {url}\n")
            f.write(f"Scanned: {report['scanned_at']}\n")
            f.write("=" * 70 + "\n\n")
            for r in results:
                f.write(f"[{r['severity'].upper()}] {r['vector']}\n")
                f.write(f"  Origin sent : {r['origin_sent']}\n")
                f.write(f"  Status      : {r['status']}\n")
                f.write(f"  ACAO        : {r['acao']}\n")
                f.write(f"  ACAC        : {r['acac']}\n")
                f.write(f"  Vary:Origin : {r['vary_includes_origin']}\n")
                f.write(f"  Note        : {r['note']}\n\n")
            f.write("\n")

        with open(jsonl_path, mode) as f:
            f.write(json.dumps(report) + "\n")

        return jsonl_path, outpath

    # --- folder mode (original behavior) ---
    if os.path.exists(outpath) and not os.path.isdir(outpath):
        sys.exit(
            f"[!] Error: '{outpath}' already exists as a file, not a directory.\n"
            f"    Choose a different -o name, or delete/rename that file first."
        )
    os.makedirs(outpath, exist_ok=True)
    safe_name = urlparse(url).netloc.replace(":", "_") or "target"
    json_path = os.path.join(outpath, f"{safe_name}_cors_results.json")
    txt_path = os.path.join(outpath, f"{safe_name}_cors_results.txt")

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    with open(txt_path, "w") as f:
        f.write(f"CORS Test Results -- {url}\n")
        f.write(f"Scanned: {report['scanned_at']}\n")
        f.write("=" * 70 + "\n\n")
        for r in results:
            f.write(f"[{r['severity'].upper()}] {r['vector']}\n")
            f.write(f"  Origin sent : {r['origin_sent']}\n")
            f.write(f"  Status      : {r['status']}\n")
            f.write(f"  ACAO        : {r['acao']}\n")
            f.write(f"  ACAC        : {r['acac']}\n")
            f.write(f"  Vary:Origin : {r['vary_includes_origin']}\n")
            f.write(f"  Note        : {r['note']}\n\n")

    return json_path, txt_path


def print_summary(results):
    candidates = [r for r in results if r["severity"] == "candidate"]
    infos = [r for r in results if r["severity"] == "info"]
    print("\n" + colorize("=" * 60, C.CYAN))
    print(colorize("SUMMARY", C.BOLD))
    print(colorize("=" * 60, C.CYAN))
    print(f"  Total vectors tested : {len(results)}")
    print(f"  {colorize('Candidates', C.RED)}           : {len(candidates)}")
    print(f"  {colorize('Informational', C.YELLOW)}        : {len(infos)}")
    if candidates:
        print(colorize(
            "\n  Candidates still need the manual checklist from cors-hunter.md\n"
            "  (credential-scope check, impact check, browser-truth check) before reporting.",
            C.YELLOW))


def main():
    ap = argparse.ArgumentParser(description="CORS misconfiguration testing tool")
    ap.add_argument("-u", "--url", help="single target URL")
    ap.add_argument("-l", "--list", help="file with one target URL per line")
    ap.add_argument("-c", "--cookie", help="cookie header value (for impact/credential testing)")
    ap.add_argument("-t", "--base-domain",
                     help="base/trusted domain for bypass variant generation (auto-derived per-target if omitted)")
    ap.add_argument("-r", "--rate", type=float, default=1.0,
                     help="delay in seconds between requests (default: 1 -- keep this sane)")
    ap.add_argument("-o", "--outdir", default="cors_hunter_out", help="output directory")
    args = ap.parse_args()

    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        with open(args.list) as f:
            targets.extend(line.strip() for line in f if line.strip())

    if not targets:
        ap.error("provide -u <url> or -l <file>")

    # If -o looks like a file (has an extension, e.g. "find_cors.txt"), write
    # everything into that one file instead of creating a folder.
    single_file_mode = os.path.splitext(args.outdir)[1] != ""

    grand_total_candidates = 0
    for i, url in enumerate(targets):
        base_domain = args.base_domain or urlparse(url).netloc
        results = run(url, args.cookie, base_domain, args.rate)
        path_a, path_b = write_outputs(
            url, results, args.outdir,
            single_file_mode=single_file_mode,
            first_write=(i == 0),
        )
        print_summary(results)
        print(colorize(f"\n[*] Saved: {path_a}", C.CYAN))
        print(colorize(f"[*] Saved: {path_b}\n", C.CYAN))
        grand_total_candidates += len([r for r in results if r["severity"] == "candidate"])

    if len(targets) > 1:
        print(colorize(
            f"\n[*] All {len(targets)} target(s) scanned. {grand_total_candidates} total candidate(s).",
            C.BOLD))


if __name__ == "__main__":
    main()
