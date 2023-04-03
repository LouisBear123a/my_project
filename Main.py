import requests
import argparse
import re
from urllib.parse import urlparse, urlunparse, urljoin
import nmap
from zap_scanner import ZapScanner
from nessus_rest import NessusAPI
from openvas_rest import OpenVASAPI
from vulnerability_reporter import generate_vulnerability_report
from vulnerability_attacker import exploit_vulnerabilities
from lfi_rfi_payloads import lfi_rfi_payloads

def get_links(url):
    print(f"[+] Getting links from {url}")
    response = requests.get(url)
    return re.findall('(?:href=")(.*?)"', response.content.decode())

def crawl(url, depth, vulnerabilities):
    links = get_links(url)
    for link in links:
        href = urljoin(url, link)
        if depth > 1:
            crawl(href, depth-1, vulnerabilities)
        if is_vulnerable_to_lfi_rfi(href):
            vulnerabilities.append((url, href))

def is_vulnerable_to_lfi_rfi(url):
    parsed_url = urlparse(url)
    for payload in lfi_rfi_payloads:
        path = parsed_url.path + payload
        url_to_check = urlunparse((parsed_url.scheme, parsed_url.netloc, path, parsed_url.params, parsed_url.query, parsed_url.fragment))
        response = requests.get(url_to_check)
        if payload.split("/")[-1] in response.text:
            print(f"[!] Found LFI/RFI vulnerability: {url_to_check}")
            return True
    return False

def scan_vulnerabilities(urls, open_ports, proxy_host, proxy_port):
    vulnerability_results = {}
    
    # Scan for vulnerabilities using ZAP scanner
    zap = ZapScanner()
    zap_results = zap.scan_urls(urls, open_ports, proxy_host=proxy_host, proxy_port=proxy_port)
    for url, results in zap_results.items():
        if url not in vulnerability_results:
            vulnerability_results[url] = {}
        vulnerability_results[url].update(results)

    # Scan for vulnerabilities using Nessus scanner
    nessus = NessusAPI()
    nessus.login()
    for url in urls:
        nessus_results = nessus.scan(url)
        if nessus_results:
            if url not in vulnerability_results:
                vulnerability_results[url] = {}
            vulnerability_results[url].update(nessus_results)
    nessus.logout()

    # Scan for vulnerabilities using OpenVAS scanner
    openvas = OpenVASAPI()
    openvas.login()
    for url in urls:
        openvas_results = openvas.scan(url)
        if openvas_results:
            if url not in vulnerability_results:
                vulnerability_results[url] = {}
            vulnerability_results[url].update(openvas_results)
    openvas.logout()

    return vulnerability_results
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web vulnerability scanner")
    parser.add_argument("url", help="The URL of the website to scan")
    parser.add_argument("-d", "--depth", type=int, default=2, help="The depth of the crawling (default: 2)")
    parser.add_argument("-o", "--output", default="report.txt", help="The output file for the vulnerability report (default: report.txt)")
    parser.add_argument("-a", "--attack", action="store_true", help="Whether to exploit the vulnerabilities found (default: False)")
    parser.add_argument("-p", "--proxy", nargs=2, metavar=("host", "port"), help="Use a proxy server to perform the scans")
    args = parser.parse_args()

    urls = [args.url]
    open_ports = []
    proxy_host = None
    proxy_port = None

    # Check if a proxy server is specified
    if args.proxy:
        proxy_host, proxy_port = args.proxy
        proxy_port = int(proxy_port)

    # Crawl the website to find vulnerabilities
    vulnerabilities = []
    crawl(args.url, args.depth, vulnerabilities)
    print(f"\n[+] Found {len(vulnerabilities)} vulnerabilities")
    if vulnerabilities:
        for vulnerability in vulnerabilities:
            print(f"    - {vulnerability[0]} is vulnerable to LFI/RFI attacks through {vulnerability[1]}")

    # Scan for vulnerabilities using various scanners
    vulnerability_results = scan_vulnerabilities(urls, open_ports, proxy_host, proxy_port)

    # Merge the vulnerabilities found through crawling and scanning
    for url, results in vulnerability_results.items():
        if url in [v[0] for v in vulnerabilities]:
            for vulnerability in vulnerabilities:
                if vulnerability[0] == url:
                    if "LFI/RFI" in results:
                        vulnerability[2] = results["LFI/RFI"]
                    if "XSS" in results:
                        vulnerability[3] = results["XSS"]
                    if "SQL Injection" in results:
                        vulnerability[4] = results["SQL Injection"]
                    if "Remote Code Execution" in results:
                        vulnerability[5] = results["Remote Code Execution"]
                    if "File Inclusion" in results:
                        vulnerability[6] = results["File Inclusion"]
                    if "Command Injection" in results:
                        vulnerability[7] = results["Command Injection"]
        else:
            for vuln_type, result in results.items():
                vulnerabilities.append((url, "", result.get("severity", ""), "", "", "", "", ""))
                for vulnerability in vulnerabilities:
                    if vulnerability[0] == url and vulnerability[2] == result["severity"]:
                        if vuln_type == "LFI/RFI":
                            vulnerability[1] = "LFI/RFI"
                            vulnerability[2] = result[vuln_type]
                        elif vuln_type == "XSS":
                            vulnerability[3] = result[vuln_type]
                        elif vuln_type == "SQL Injection":
                            vulnerability[4] = result[vuln_type]
                        elif vuln_type == "Remote Code Execution":
                            vulnerability[5] = result[vuln_type]
                        elif vuln_type == "File Inclusion":
                            vulnerability[6] = result[vuln_type]
                        elif vuln_type == "Command Injection":
                            vulnerability[7] = result[vuln_type]
    # Generate and save the vulnerability report
    report = generate_vulnerability_report(vulnerabilities)
    with open(args.output, "w") as f:
        f.write(report)
    print(f"[+] Vulnerability report saved to {args.output}")

    # Exploit vulnerabilities if specified
    if args.attack:
        print("[+] Exploiting vulnerabilities")
        exploit_vulnerabilities(vulnerabilities)


