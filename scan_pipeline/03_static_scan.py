#!/usr/bin/env python3
import os, sys, json, argparse, subprocess

OUTPUT_DIR = "output"
SEMREG_RAW = "output/semgrep_raw.json"
FINDINGS_JSON = "output/findings.json"

def ensure_output():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def run_semgrep(target):
    cmd = ["semgrep", "--config", "p/python", "--json", "--output", SEMREG_RAW, target]
    try:
        subprocess.run(cmd, check=True)
    except:
        subprocess.run([sys.executable, "-m", "semgrep", "--config", "p/python",
                        "--json", "--output", SEMREG_RAW, target], check=True)

def load_semgrep_raw():
    if not os.path.exists(SEMREG_RAW):
        return []
    with open(SEMREG_RAW, "r", encoding="utf-8") as f:
        return json.load(f).get("results", [])

def normalize_result(r, idx):
    extra = r.get("extra", {}) or {}
    return {
        "id": f"AUTO-{idx:04d}",
        "tool": "semgrep",
        "vuln_name": extra.get("message") or r.get("check_id"),
        "cwe": extra.get("metadata", {}).get("cwe", ""),
        "cve": "",
        "file": r.get("path"),
        "line": r.get("start", {}).get("line", ""),
        "severity": extra.get("severity", "Medium"),
        "confidence": 0.7
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    ensure_output()
    run_semgrep(args.target)
    results = load_semgrep_raw()
    findings = [normalize_result(r, i+1) for i, r in enumerate(results)]
    with open(FINDINGS_JSON, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    print(f"Wrote {len(findings)} findings to {FINDINGS_JSON}")

if __name__ == "__main__":
    main()
