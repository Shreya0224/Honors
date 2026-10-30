# Exp 6: Kioptrix Exploitation + Privilege Escalation Simulator

# Step 1: Target fingerprint
target = {"ip": "192.168.56.105", "smb": "Samba 2.2.1a", "os": "Linux 2.4.7 (RedHat 7.2)"}
VULN_DB = {"Samba 2.2.1a": ("CVE-2003-0201 trans2open", "exploit/linux/samba/trans2open")}

print(f"Target {target['ip']}: SMB={target['smb']}, OS={target['os']}")

# Step 2: Match exploit
cve, module = VULN_DB[target["smb"]]
print(f"Matched: {cve} -> {module}")

# Step 3: Simulate initial exploitation
print("Sending trans2open overflow ... payload linux/x86/shell_reverse_tcp ...")
initial_uid = "uid=99(nobody)"  # Samba exploit often lands as nobody/admin first
print(f"Session 1 opened: {initial_uid}")

# Step 4: Privilege-escalation enumeration (simulated outputs)
enum = {
    "uname -r": "2.4.7-10",
    "sudo -l": "(ALL) NOPASSWD: /usr/bin/vim",  # misconfig found!
    "suid_bins": ["/usr/bin/vim", "/bin/mount"],
    "kernel_exploit_available": "ptrace-kmod (CVE-2003-0127)",
}
print("Enumeration:", enum)

# Step 5: Choose privesc path - sudo vim is fastest
if "NOPASSWD" in enum["sudo -l"]:
    print("Using: sudo vim -c ':!/bin/sh' -> root shell (GTFOBins technique)")
    final_uid = "uid=0(root)"
else:
    print(f"Using kernel exploit: {enum['kernel_exploit_available']}")
    final_uid = "uid=0(root)"

print("whoami =>", final_uid)
print(
    "cat /etc/shadow hash captured. ROOT ACQUIRED."
    if "0(root)" in final_uid
    else "Escalation FAILED"
)
