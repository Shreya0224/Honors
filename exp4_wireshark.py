# Exp 4: Wireshark-style Cleartext Detector (simulated packets)

# Step 1: Simulated captured packets (as exported from Wireshark -> tshark -T fields)
packets = [
    {"no": 1, "proto": "HTTPS", "info": "TLSv1.3 Application Data", "payload": "encrypted blob 9f3a..."},
    {"no": 2, "proto": "HTTP", "info": "POST /login.php", "payload": "username=sudan&password=Tiwari123"},
    {"no": 3, "proto": "FTP", "info": "USER anonymous", "payload": "USER admin PASS admin123"},
    {"no": 4, "proto": "SSH", "info": "Encrypted session", "payload": "AES-CTR ciphertext"},
    {"no": 5, "proto": "TELNET", "info": "Login:", "payload": "USER root PASS toor"},
    {"no": 6, "proto": "DNS", "info": "Query mail.example-org.com", "payload": "A record query"},
]

# Step 2: Detection logic - cleartext protocols + credential keywords
CLEAR = {"HTTP", "FTP", "TELNET", "SMTP", "POP"}
KEYWORDS = ["username", "password", "passwd", "user ", "pass ", "cookie", "authorization"]

# Step 3: Analyse each packet
print("Packet Analysis - Unencrypted Data Detection")
leaks = 0
for p in packets:
    is_clear = p["proto"] in CLEAR
    has_secret = any(k.lower() in p["payload"].lower() for k in KEYWORDS)

    if is_clear and has_secret:
        status = "LEAK - UNENCRYPTED CREDENTIALS"
    elif is_clear:
        status = "cleartext"
    else:
        status = "OK/encrypted"

    if "LEAK" in status:
        leaks += 1

    print(f"  #{p['no']:02d} {p['proto']:6s} | {p['info']:<24s} => {status}")

print(f"\nResult: {leaks} packets leak credentials in cleartext.")
print("Recommendation: enforce HTTPS, SFTP/SSH, disable Telnet/FTP.")
