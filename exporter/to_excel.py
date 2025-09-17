#!/usr/bin/env python3
import os, json, sys, pandas as pd

STARTUP_NAME = "VulnSage"
EXCEL_NAME = f"GC_PS_01_{STARTUP_NAME}.xlsx"
FINDINGS_JSON = "output/findings.json"

LANG_MAP = {
    ".py": "Python", ".java": "Java", ".c": "C/C++", ".cpp": "C/C++",
    ".cs": "C#", ".php": "PHP"
}

def guess_lang(fname):
    _, ext = os.path.splitext(fname or "")
    return LANG_MAP.get(ext.lower(), "Unknown")

def load_findings():
    if not os.path.exists(FINDINGS_JSON):
        print("ERROR: findings.json not found")
        sys.exit(1)
    with open(FINDINGS_JSON, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    rows, ser = [], 1
    for f in load_findings():
        rows.append({
            "Ser": ser,
            "Name of Application Tested": STARTUP_NAME,
            "Language": guess_lang(f.get("file", "")),
            "Vulnerability Found": f.get("vuln_name", ""),
            "CVE": f.get("cve", ""),
            "File Name": f.get("file", ""),
            "Line of Code": f.get("line", ""),
            "Detection Accuracy": f"Confidence {f.get('confidence',0.7)}; Severity {f.get('severity','Medium')}"
        })
        ser += 1
    os.makedirs("output", exist_ok=True)
    outpath = os.path.join("output", EXCEL_NAME)
    pd.DataFrame(rows).to_excel(outpath, index=False)
    print(f"Written Excel: {outpath}")

if __name__ == "__main__":
    main()
