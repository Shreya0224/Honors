# Exp 2: Phishing Simulation & URL Trust Verifier
import re


# Step 1: Feature-based phishing URL detector
def url_score(url):
    score, flags = 0, []

    if re.match(r"https?://\d+\.\d+\.\d+\.\d+", url):  # IP instead of domain
        score += 3
        flags.append("IP-based URL")

    if "@" in url:
        score += 2
        flags.append("'@' trick")

    if len(url) > 75:
        score += 1
        flags.append("excessively long URL")

    if url.count("-") >= 3 or "secure-login" in url or "verify" in url:
        score += 2
        flags.append("lookalike / urgency keywords")

    if url.startswith("http://"):  # no TLS
        score += 1
        flags.append("no HTTPS")

    return score, flags


# Step 2: Craft simulated campaign (safe lab mock, no real sending)
users = [
    "sudan.tiwari@example-org.com",
    "hr@example-org.com",
    "finance@example-org.com",
    "it@example-org.com",
    "intern@example-org.com",
]

test_urls = {
    "sudan.tiwari@example-org.com": "http://192.168.1.10/secure-login-verify-account-update.php",
    "hr@example-org.com": "https://portal.example-org.com/login",
    "finance@example-org.com": "http://example-org-secure-login.com@evil.com/payroll",
    "it@example-org.com": "https://mail.example-org.com/reset",
    "intern@example-org.com": "http://bit.ly/3xpay-slip-verify",
}

# Step 3: Process each target: score lure + simulate behaviour
print("Phishing Simulation Report (LAB MOCK - no real emails sent)")
for u in users:
    url = test_urls[u]
    s, f = url_score(url)
    verdict = "PHISHING-LIKE" if s >= 3 else "SUSPICIOUS" if s >= 1 else "LIKELY-LEGIT"
    print(f"\nTo: {u}\n  URL: {url}\n  Risk={s} {f} => {verdict}")

# Step 4: Aggregate human-response metrics (simulated clicks)
simulated_clicks = 2  # 2 of 5 clicked in mock
print(f"\nClick rate: {simulated_clicks}/{len(users)} = {simulated_clicks/len(users)*100:.0f}%")
print("Action: users with clicks enrolled for awareness training.")
