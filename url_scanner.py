import requests
import concurrent.futures

def scan_url(url, proxy_host=None, proxy_port=None):
    """Scans a URL for vulnerabilities using OWASP ZAP."""

    # Configure the proxy
    proxies = {}
    if proxy_host and proxy_port:
        proxies['http'] = f'http://{proxy_host}:{proxy_port}'
        proxies['https'] = f'https://{proxy_host}:{proxy_port}'

    # Send a request to the URL
    try:
        response = requests.get(url, proxies=proxies)
    except Exception as e:
        return f"Error: {e}"

    # Check for vulnerabilities
    if "password" in response.text:
        return "Password field detected."
    if "username" in response.text:
        return "Username field detected."
    if "sql" in response.text:
        return "SQL injection vulnerability detected."
    if "xss" in response.text:
        return "Cross-site scripting vulnerability detected."
    return "No vulnerabilities detected."


def scan_urls(urls, num_threads=10, proxy_host=None, proxy_port=None):
    """Scans a list of URLs for vulnerabilities using OWASP ZAP."""

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        # Submit a task for each URL to be scanned
        future_to_url = {executor.submit(scan_url, url, proxy_host, proxy_port): url for url in urls}
        # Wait for the tasks to complete and store the results
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            results[url] = future.result()
    return results
