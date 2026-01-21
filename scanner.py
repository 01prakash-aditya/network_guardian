import subprocess
import re
import os

def get_trusted_ips():
    """Reads the trusted_ips.txt file and returns a set of IPs."""
    if not os.path.exists('trusted_ips.txt'):
        return set()
    with open('trusted_ips.txt', 'r') as f:
        return {line.strip() for line in f if line.strip()}

def get_network_interfaces():
    """Get available network interfaces."""
    try:
        cmd = ["sudo", "arp-scan", "--interface=list"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        interfaces = []
        for line in result.stdout.splitlines():
            if line.strip() and not line.startswith('Interface'):
                parts = line.split()
                if parts:
                    interfaces.append(parts[0])
        return interfaces
    except:
        return ["eth0", "wlan0"]

def parse_arp_output(output, trusted_ips):
    """Parse arp-scan output and return device list."""
    devices = []
    pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.*)")
    
    for line in output.splitlines():
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

def run_network_scan(scan_type="local", **kwargs):
    """Run different types of arp-scan operations."""
    trusted_ips = get_trusted_ips()
    
    if scan_type == "local":
        # Basic local network scan
        cmd = ["sudo", "arp-scan", "-l"]
    
    elif scan_type == "interface":
        # Scan with specific interface
        interface = kwargs.get('interface', 'eth0')
        cmd = ["sudo", "arp-scan", "-I", interface, "-l"]
    
    elif scan_type == "subnet":
        # Scan specific subnet
        subnet = kwargs.get('subnet', '192.168.1.0/24')
        cmd = ["sudo", "arp-scan", subnet]
    
    elif scan_type == "retry":
        # Scan with custom retry count for more accuracy
        retry_count = kwargs.get('retry', 3)
        cmd = ["sudo", "arp-scan", "-l", "-r", str(retry_count)]
    
    elif scan_type == "bandwidth":
        # Scan with bandwidth control
        bandwidth = kwargs.get('bandwidth', 256)
        cmd = ["sudo", "arp-scan", "-l", "-b", str(bandwidth)]
    
    elif scan_type == "duplicates":
        # Check for duplicate IP addresses
        cmd = ["sudo", "arp-scan", "-l", "-d"]
    
    elif scan_type == "random_mac":
        # Scan with randomized source MAC
        cmd = ["sudo", "arp-scan", "-l", "-R"]
    
    elif scan_type == "verbose":
        # Verbose scan with packet details
        cmd = ["sudo", "arp-scan", "-l", "-v"]
    
    else:
        cmd = ["sudo", "arp-scan", "-l"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        devices = parse_arp_output(result.stdout, trusted_ips)
        
        # Add metadata
        return {
            "devices": devices,
            "scan_type": scan_type,
            "total": len(devices),
            "safe_count": sum(1 for d in devices if d['status'] == 'Safe'),
            "unsafe_count": sum(1 for d in devices if d['status'] != 'Safe')
        }
    except subprocess.TimeoutExpired:
        return {"error": "Scan timeout - operation took too long"}
    except Exception as e:
        return {"error": str(e)}

def run_custom_scan(target):
    """Run scan on custom IP or subnet."""
    trusted_ips = get_trusted_ips()
    cmd = ["sudo", "arp-scan", target]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        devices = parse_arp_output(result.stdout, trusted_ips)
        return devices
    except Exception as e:
        return {"error": str(e)}