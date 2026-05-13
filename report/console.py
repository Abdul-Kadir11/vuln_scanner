def print_results(results):

    print("\n=== SCAN COMPLETE ===\n")

    for plugin in results:

        if not plugin["issues"]:
            continue

        print(f"[{plugin['category'].upper()}] {plugin['plugin']}")

        for issue in plugin["issues"]:
            print(f"  [{issue['severity']}] {issue['title']}")

            if issue["cve"]:
                print(f"      CVE: {issue['cve']}")

            if issue["port"]:
                print(f"      Port: {issue['port']}")

        print()
