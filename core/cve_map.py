CVE_DB = {
    "vsftpd 2.3.4": "CVE-2011-2523",
    "OpenSSH_4": "CVE-2008-0166",
    "Samba 3": "CVE-2007-2447",
    "Apache 2.2": "Multiple known CVEs",
    "Apache/2.2": "Multiple known CVEs",
    "mysql 5.0": "Multiple known CVEs"
}

def match_cve(text):
    if not text:
        return None

    for key in CVE_DB:
        if key.lower() in text.lower():
            return CVE_DB[key]

    return None
