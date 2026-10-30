# Exp 9: Server/Firewall Log Anomaly Detector
from collections import Counter

# Step 1: Sample logs (Apache + firewall mix)
logs = [
    '192.168.56.10 - - [06/Oct/2026:10:01:02] "GET /index.html HTTP/1.1" 200 1024',
    '203.0.113.7 - - [06/Oct/2026:10:01:10] "POST /login.php HTTP/1.1" 401 512',
    '203.0.113.7 - - [06/Oct/2026:10:01:12] "POST /login.php HTTP/1.1" 401 512',
    '203.0.113.7 - - [06/Oct/2026:10:01:14] "POST /login.php HTTP/1.1" 401 512',
    '203.0.113.7 - - [06/Oct/2026:10:01:16] "POST /login.php HTTP/1.1" 401 512',
    '203.0.113.7 - - [06/Oct/2026:10:01:18] "POST /login.php HTTP/1.1" 401 512',
    '203.0.113.7 - - [06/Oct/2026:10:01:20] "POST /login.php HTTP/1.1" 401 512',
    '198.51.100.9 - - [06/Oct/2026:10:02:01] "GET /products?id=1\' OR \'1\'=\'1 HTTP/1.1" 500 0',
    '198.51.100.9 - - [06/Oct/2026:10:02:05] "GET /..%2f..%2fetc%2fpasswd HTTP/1.1" 403 0',
    '192.168.56.10 - - [06/Oct/2026:03:15:00] "GET /backup.zip HTTP/1.1" 200 50000000',
    'FIREWALL DENY 203.0.113.7 -> 192.168.56.101:445 TCP',
    'FIREWALL DENY 203.0.113.7 -> 192.168.56.101:445 TCP',
]

# Step 2: Parse + detect patterns
fails = Counter()
print("Anomaly Scan:")
for line in logs:
    if "401" in line:  # failed login
        ip = line.split()[0]
        fails[ip] += 1
    if "OR" in line and "1'='1" in line:
        print(f"  [SQLi PROBE] {line}")
    if "..%2f" in line.lower() or "../" in line:
        print(f"  [PATH TRAVERSAL] {line}")
    if "backup.zip" in line and "03:15" in line:
        print(f"  [ODD-HOUR EXFIL] {line}")
    if "FIREWALL DENY" in line and ":445" in line:
        print(f"  [SMB SCAN/BLOCKED] {line}")

# Step 3: Brute-force rule: >=5 fails from one IP
for ip, c in fails.items():
    if c >= 5:
        print(f"  [BRUTE FORCE] {ip} -> {c} failed logins => block IP, force MFA reset")

print(f"\nSummary: {dict(fails)} failed-login counts. Recommend WAF + fail2ban + SIEM alert.")
