import json
from datetime import datetime


def save_report(target, results):
    report = {
        "target": target,
        "timestamp": str(datetime.now()),
        "findings": results
    }

    filename = f"report_{target.replace('://','_').replace('/','_')}.json"

    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\n[+] Report saved: {filename}")
