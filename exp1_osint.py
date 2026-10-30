# Exp 1: OSINT Visibility Audit Simulator

# Step 1: Take target organization input
target = "example-org.com"

# Step 2: Simulated public footprint data (as collected via whois, dig, theHarvester)
footprint = {
    "domain": target,
    "whois": {"registrar": "GoDaddy", "expiry": "2026-05-01", "privacy": False},
    "subdomains": [
        "www.example-org.com",
        "mail.example-org.com",
        "test.example-org.com",
        "vpn.example-org.com",
    ],
    "open_ports_hint": ["80/http", "443/https", "21/ftp", "22/ssh"],
    "emails_found": [
        "admin@example-org.com",
        "hr@example-org.com",
        "sudan.tiwari@example-org.com",
    ],
    "tech_stack": ["Apache 2.2.15 (EOL)", "PHP 5.4", "WordPress 4.9"],
    "social_mentions": 14,
}


# Step 3: Risk scoring logic
def audit_score(fp):
    score = 0
    reasons = []

    if not fp["whois"]["privacy"]:  # WHOIS privacy disabled exposes owner
        score += 15
        reasons.append("WHOIS privacy disabled (+15)")

    score += len(fp["subdomains"]) * 3  # each subdomain widens surface
    reasons.append(f"{len(fp['subdomains'])} subdomains found (+{len(fp['subdomains'])*3})")

    score += len(fp["emails_found"]) * 4
    reasons.append(f"{len(fp['emails_found'])} emails harvested (+{len(fp['emails_found'])*4})")

    for tech in fp["tech_stack"]:  # outdated tech = high weight
        if "EOL" in tech or "5.4" in tech or "4.9" in tech:
            score += 10
            reasons.append(f"Outdated tech {tech} (+10)")

    if "21/ftp" in fp["open_ports_hint"]:
        score += 10
        reasons.append("Cleartext FTP exposed (+10)")

    return min(score, 100), reasons


# Step 4: Process and produce audit output
risk, reasons = audit_score(footprint)

print(f"Visibility Audit for: {target}")
print(f"Subdomains: {footprint['subdomains']}")
print(f"Emails: {footprint['emails_found']}")
print("Findings:")
for r in reasons:
    print(" -", r)
print(f"Visibility Risk Score: {risk}/100")

grade = "Critical" if risk >= 70 else "High" if risk >= 50 else "Medium" if risk >= 30 else "Low"
print("Exposure Grade:", grade)
