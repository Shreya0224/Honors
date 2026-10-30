# Exp 10: Nessus-style Vulnerability Assessment + VAPT Report Compiler
from collections import Counter

# Step 1: Simulated Nessus export (plugin results)
findings = [
    {"host": "192.168.56.101", "plugin": "vsftpd backdoor", "cve": "CVE-2011-2523", "cvss": 9.8},
    {"host": "192.168.56.101", "plugin": "Apache 2.2 EOL", "cve": "CVE-2017-9798", "cvss": 7.5},
    {"host": "192.168.56.102", "plugin": "SMBv1 enabled", "cve": "CVE-2017-0144", "cvss": 8.1},
    {"host": "192.168.56.102", "plugin": "RDP NLA disabled", "cve": "CVE-2019-0708", "cvss": 9.8},
    {"host": "192.168.56.1", "plugin": "SSH weak cipher", "cve": "CVE-2008-5161", "cvss": 4.3},
    {"host": "192.168.56.1", "plugin": "HTTP TRACE enabled", "cve": "CVE-2003-1567", "cvss": 3.7},
]


# Step 2: Classify by CVSS (Nessus severity scale)
def sev(cvss):
    if cvss >= 9.0:
        return "Critical"
    if cvss >= 7.0:
        return "High"
    if cvss >= 4.0:
        return "Medium"
    return "Low"


counts = Counter(sev(f["cvss"]) for f in findings)

# Step 3: Compile formal report summary
print("=" * 58)
print("VAPT REPORT - Confidential | Target: 192.168.56.0/24 | Date: 06-Oct-2026")
print("Scanner: Nessus Essentials (simulated) | Analyst: Sudan Tiwari (Roll 21)")
print("=" * 58)
print(f"Hosts scanned: 3 | Findings: {len(findings)}")
for s in ["Critical", "High", "Medium", "Low"]:
    print(f"  {s:<8}: {counts.get(s, 0)}")

print("\nTop findings (sorted by CVSS):")
for f in sorted(findings, key=lambda x: -x["cvss"]):
    print(f"  [{sev(f['cvss']):8s}] {f['host']} | {f['plugin']} | {f['cve']} | CVSS {f['cvss']}")

print("\nRemediation priority: Critical within 7 days (isolate SMBv1/RDP, rebuild vsftpd).")
print("Retest: rescan after patch; risk accepted only for Low with compensating control.")
print("Conclusion: Network NOT secure for production - 2 Critical paths allow remote compromise.")
