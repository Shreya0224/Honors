# Exp 7: Blind SQL Injection Extractor (Boolean-based, DVWA mock)

# Step 1: Mock vulnerable server - hidden secret, only True/False visible
SECRET = "dvwa7"  # simulated DB version / first table chars (unknown to attacker)


def oracle(payload_condition):
    # Server evaluates: SELECT * FROM users WHERE id=1 AND (<condition>)
    # We emulate with Python eval on SECRET for demo
    return eval(payload_condition, {"SECRET": SECRET})


# Step 2: Attacker extracts one char via binary search on ASCII
def extract_char(pos):
    lo, hi = 32, 126  # printable range
    while lo < hi:
        mid = (lo + hi) // 2
        # Ask: is SECRET[pos] > chr(mid)? -> payload: ord(SECRET[pos]) > mid
        cond = f"ord(SECRET[{pos}]) > {mid}"
        if oracle(cond):
            lo = mid + 1
        else:
            hi = mid
    return chr(lo)


# Step 3: Extract full secret length then value (length oracle simulated)
print("Blind SQLi extraction started (DVWA low-security mock)...")
extracted = ""
for i in range(len(SECRET)):
    ch = extract_char(i)
    extracted += ch
    print(f"  Position {i+1}: '{ch}' (requests ~7)")

print(f"Extracted value: '{extracted}'")
print("Match:", extracted == SECRET, "-> DB info exfiltrated without seeing query output.")
