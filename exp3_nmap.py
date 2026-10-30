# Exp 3: Live Host Discovery + Port Scan + OS Fingerprint (Simulator)
import socket

# Step 1: Simulated sweep result (in real lab: nmap -sn 192.168.56.0/24)
subnet_hosts = {
    "192.168.56.1": {"alive": True, "ttl": 64, "ports": {22: "ssh", 80: "http"}},
    "192.168.56.101": {
        "alive": True,
        "ttl": 64,
        "ports": {21: "ftp", 22: "ssh", 80: "http", 445: "smb"},
    },
    "192.168.56.102": {
        "alive": True,
        "ttl": 128,
        "ports": {135: "msrpc", 139: "netbios", 445: "smb", 3389: "rdp"},
    },
    "192.168.56.103": {"alive": False, "ttl": None, "ports": {}},
}


# Step 2: OS guess from TTL (classic fingerprint heuristic)
def guess_os(ttl):
    if ttl is None:
        return "Unknown (host down)"
    if ttl <= 64:
        return "Linux / Unix (TTL~64)"
    if ttl <= 128:
        return "Windows (TTL~128)"
    return "Network device (TTL~255)"


# Step 3: Real localhost TCP connect scan demo (safe) + simulated net
def tcp_scan(ip, ports, timeout=0.5):
    res = {}
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            # Only actually connect when scanning localhost; else use simulated table
            if ip == "127.0.0.1":
                r = s.connect_ex((ip, p))
                res[p] = "open" if r == 0 else "closed"
            else:
                res[p] = "open" if p in subnet_hosts[ip]["ports"] else "closed"
        finally:
            s.close()
    return res


# Step 4: Process and print discovery table
print("Host Discovery + Port Scan + OS Fingerprint")
for ip, info in subnet_hosts.items():
    print(f"\n{ip}: {'UP' if info['alive'] else 'DOWN'} | OS Guess: {guess_os(info['ttl'])}")
    if info["alive"]:
        scan = tcp_scan(ip, [21, 22, 80, 135, 139, 445, 3389])
        for port, st in scan.items():
            if st == "open":
                print(f"  Port {port}/tcp OPEN ({info['ports'][port]})")

print(
    "\nLocalhost demo (127.0.0.1 ports 22,80,135,445):",
    tcp_scan("127.0.0.1", [22, 80, 135, 445]),
)
