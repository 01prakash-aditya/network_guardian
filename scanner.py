import subprocess
import re
import os

def get_trusted_ips():
    """Reads the trusted_ips.txt file and returns a set of IPs."""
    if not os.path.exists('trusted_ips.txt'):
        return set()
    with open('trusted_ips.txt', 'r') as f:
        return {line.strip() for line in f if line.strip()}

def run_network_scan():
    # Runs arp-scan on the local network
    cmd = ["sudo", "arp-scan", "-l"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    trusted_ips = get_trusted_ips()
    devices = []
    # Regex to find IP, MAC, and Vendor
    pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.*)")
    
    for line in result.stdout.splitlines():
        match = pattern.search(line)
        if match:
            ip = match.group(1)
            devices.append({
                "ip": ip,
                "mac": match.group(2),
                "vendor": match.group(3),
                "status": "Safe" if ip in trusted_ips else "Not Safe"
            })
    return devices