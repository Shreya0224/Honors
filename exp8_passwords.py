# Exp 8: Password Auditing Simulator (dictionary + strength meter)
import hashlib
import math
import string

# Step 1: Simulated /etc/shadow + AD dump (hashes of known passwords)
users = {
    "sudan (linux)": hashlib.sha256(b"password123").hexdigest(),
    "admin (windows NTLM-mock)": hashlib.md5(b"admin123").hexdigest(),
    "db_app": hashlib.sha256(b"Str0ng!Pass#2026").hexdigest(),
}

wordlist = ["123456", "password", "password123", "admin123", "qwerty", "letmein", "welcome1"]


# Step 2: Dictionary audit function
def audit(target_hash, algo="sha256"):
    for w in wordlist:
        h = (
            hashlib.sha256(w.encode()).hexdigest()
            if algo == "sha256"
            else hashlib.md5(w.encode()).hexdigest()
        )
        if h == target_hash:
            return w  # cracked
    return None


# Step 3: Strength scorer
def strength(pw):
    pool = (26 if any(c.islower() for c in pw) else 0) + (26 if any(c.isupper() for c in pw) else 0)
    pool += (10 if any(c.isdigit() for c in pw) else 0) + (
        32 if any(c in string.punctuation for c in pw) else 0
    )
    entropy = len(pw) * math.log2(pool) if pool else 0
    verdict = "WEAK" if entropy < 40 else "FAIR" if entropy < 60 else "STRONG"
    return round(entropy, 1), verdict


# Step 4: Run audit
print("Password Audit Results")
for user, h in users.items():
    algo = "md5" if "windows" in user else "sha256"
    cracked = audit(h, algo)
    demo_pw = cracked if cracked else "Str0ng!Pass#2026"
    ent, verdict = strength(demo_pw)
    result = f"CRACKED -> {cracked}" if cracked else "NOT cracked (resists dictionary)"
    print(f"  {user}: {result} | Entropy {ent} bits => {verdict}")
