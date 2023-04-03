import nmap

def scan_ports(url):
    """
    Scan the given URL for open ports and services using nmap.
    Returns a list of open ports.
    """
    nm = nmap.PortScanner()
    nm.scan(url, arguments='-sS')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
    return open_ports
