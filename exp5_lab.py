# Exp 5: Kali + VulnHub Lab Setup Checker & Basic Exploitation Simulator

# Step 1: Lab prerequisites checklist
lab = {
    "Kali VM (2024.x)": True,
    "VulnHub VM (e.g., Stapler / Basic Pentesting:1)": True,
    "Host-only network 192.168.56.0/24": True,
    "Snapshot taken": True,
    "Written authorization": True,
}

print("Pentest Lab Readiness Check")
ready = all(lab.values())
for k, v in lab.items():
    print(f"  [{'x' if v else ' '}] {k}")
print("Lab READY" if ready else "Lab NOT READY - fix missing items")

# Step 2: Simulated basic exploitation workflow
target = "192.168.56.101"
scan = {"21/ftp": "vsftpd 2.3.4 (backdoor)", "80/http": "Cuppa CMS (LFI)"}
print(f"\nTarget: {target} | Nmap found: {scan}")

# Step 3: Match vulnerability to Metasploit module and 'exploit'
exploits = {"vsftpd 2.3.4 (backdoor)": "exploit/unix/ftp/vsftpd_234_backdoor"}
chosen = exploits["vsftpd 2.3.4 (backdoor)"]
print(f"Selected module: {chosen}")
print("Setting RHOSTS=192.168.56.101, RPORT=21, PAYLOAD=cmd/unix/interact ...")

# Step 4: Simulate session result
session_opened = ready and ("vsftpd" in str(scan))
print("Exploit completed." if session_opened else "Exploit failed.")
print(
    "Meterpreter/session opened (uid=nobody) - ACCESS GAINED"
    if session_opened
    else "No session."
)
print("Next: post-exploitation enumeration for privilege escalation (see Exp 6).")
