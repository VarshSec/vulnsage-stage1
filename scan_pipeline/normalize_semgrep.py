#!/usr/bin/env python3
import json, os, sys

SEMREG_RAW = "output/semgrep_raw.json"
FINDINGS = "output/findings.json"

def severity_map(s):
    if not s: return "Medium", 0.6
    s = str(s).lower()
    if s in ("error","high"): return "High", 0.9
    if s in ("warning","medium"): return "Medium", 0.7
    if s in ("info","low"): return "Low", 0.5
    return "Medium", 0.6

def infer_cwe(extra):
    if not extra: return ""
    md = extra.get("metadata") or {}
    for k in ("cwe","cwe_ids","CWE"):
        if k in md:
            v = md[k]
            if isinstance(v, (list,tuple)) and v: return v[0]
            return str(v)
    return ""

def load_raw():
    if not os.path.exists(SEMREG_RAW):
        print("Missing semgrep_raw.json")
        sys.exit(1)
    with open(SEMREG_RAW, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("results", [])

def normalize(results):
    out = []
    idx = 1
    for r in results:
        extra = r.get("extra", {}) or {}
        path = r.get("path") or extra.get("path") or ""
        start = r.get("start") or extra.get("start") or {}
        line = start.get("line","")
        message = extra.get("message") or r.get("check_id") or "issue"
        sev, conf = severity_map(extra.get("severity") or extra.get("confidence"))
        cwe = infer_cwe(extra)
        finding = {
            "id": f"AUTO-{idx:04d}",
            "tool": "semgrep",
            "vuln_name": message,
            "cwe": cwe,
            "cve": "",
            "file": path,
            "line": line,
            "evidence": (extra.get("match") or "")[:400],
            "severity": sev,
            "confidence": round(conf,2)
        }
        out.append(finding)
        idx += 1
    return out

def main():
    results = load_raw()
    findings = normalize(results)
    os.makedirs("output", exist_ok=True)
    with open(FINDINGS, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    print(f"WROTE {len(findings)} findings to {FINDINGS}")

if __name__ == "__main__":
    main()
