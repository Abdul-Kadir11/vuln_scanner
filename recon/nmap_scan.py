import subprocess

def scan(target_ip):
    print("[+] Running recon...")

    output = subprocess.getoutput(f"nmap -sV -T4 {target_ip}")

    return output
