from datetime import datetime
import os


def generate_html_report(target, results):

    html = f"""
    <html>
    <head>
        <title>Scan Report</title>
        <style>
            body {{ font-family: Arial; }}
            table {{ border-collapse: collapse; width: 100%; }}
            td, th {{ border: 1px solid #ddd; padding: 8px; }}
        </style>
    </head>
    <body>
    <h2>Scan Report: {target}</h2>
    """

    for plugin in results:

        html += f"<h3>{plugin.get('plugin')}</h3>"
        html += "<table>"
        html += "<tr><th>Title</th><th>Severity</th><th>CVE</th></tr>"

        for issue in plugin.get("issues", []):

            html += f"""
            <tr>
                <td>{issue.get('title', '')}</td>
                <td>{issue.get('severity', '')}</td>
                <td>{issue.get('cve', '')}</td>
            </tr>
            """

        html += "</table><br>"

    html += "</body></html>"

    filename = f"report_{target.replace('http://','').replace('https://','').replace(':','_')}.html"

    with open(filename, "w") as f:
        f.write(html)

    print(f"[+] HTML report generated: {filename}")
