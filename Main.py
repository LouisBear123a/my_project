from modules.url_scanner import scan_urls
from modules.selenium_crawler import crawl_website
from modules.port_scanner import scan_ports
from modules.vulnerability_scanner import scan_vulnerabilities
from modules.attacks import automate_attacks

def crawl_and_scan():
    website_url = input("Enter the website URL to crawl and scan: ")
    num_threads = int(input("Enter the number of threads for URL scanning: "))

    # Configure Selenium web driver to use Burp Suite as a proxy
    proxy_host = 'localhost'
    proxy_port = 8080
    options = ChromeOptions()
    options.add_argument(f'--proxy-server=http://{proxy_host}:{proxy_port}')
    driver = Chrome(options=options)

    crawl_results = crawl_website(website_url, use_headless_browser=True, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3", driver=driver)
    print("Crawl Results: ")
    print(crawl_results)
    urls = list(crawl_results.keys())

    # Scan for open ports and services
    open_ports = scan_ports(website_url)
    print("Open Ports: ")
    print(open_ports)

    # Add open ports to urls list to scan
    for port in open_ports:
        url = f"{website_url}:{port}"
        urls.append(url)

    # Scan URLs for vulnerabilities using upgraded scanner
    vulnerability_results = scan_vulnerabilities(urls, open_ports, proxy_host, proxy_port)
    print("Vulnerability Scan Results: ")
    for url, results in vulnerability_results.items():
        print(f"Results for {url}:")
        print(results)

    # Combine scan results
    scan_results = {}
    for url in urls:
        scan_results[url] = {}
        if url in vulnerability_results:
            scan_results[url].update(vulnerability_results[url])

    print("Scan Results: ")
    for url, results in scan_results.items():
        print(f"Results for {url}:")
        print(results)

    # Automate attacks based on scan results
    automate_attacks(scan_results)

    driver.quit()

def main():
    while True:
        print("1. Website crawling and scanning")
        print("2. Test user authentication mechanisms")
        print("3. Quit")
        choice = input("Enter your choice: ")

        if choice == "1":
            crawl_and_scan()
        elif choice == "2":
            target_url = input("Enter the target URL to test user authentication mechanisms: ")
            username_list_path = input("Enter the path to the file containing the list of usernames: ")
            password_list_path = input("Enter the path to the file containing the list of passwords: ")
            hydra_options = input("Enter additional options for thc-hydra (optional): ")
            automate_attacks({target_url: {"username": {"form_input_name": "", "value": ""},
                                           "password": {"form_input_name": "", "value": ""}}}, 
                              username_list_path, password_list_path, hydra_options)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")
            continue

if __name__ == "__main__":
    main()
