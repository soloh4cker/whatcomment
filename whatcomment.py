import argparse
import requests
from bs4 import BeautifulSoup, Comment
import re
from urllib.parse import urljoin

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="WhatComment is a Penetration testing tool to scan a single page for HTML comments for sensitive information. "
                    "For now, current v1.0 can only find JS Files, Email Addresses, and Admin Panels/Pages. "
                    "This tool does not crawl or spider the whole domain. It works on a single page for now.",
        epilog="You must provide the complete URI of the page you want to test. For example, 'whatcomment.py -u https://testweb.com/page1'.",
        add_help=True)
    parser.add_argument('-u', '--url', required=True, help='URL to fetch and analyze')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
    return parser.parse_args()

def fetch_html(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching the URL {url}: {str(e)}")
        return None

def find_comments(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    return soup.find_all(string=lambda text: isinstance(text, Comment))

def extract_sensitive_data(comments, base_url):
    data = {
        'js_files': [],
        'emails': [],
        'admin_urls': []
    }
    js_pattern = re.compile(r'(/[\w/.\-]+\.js)')
    email_pattern = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
    admin_url_pattern = re.compile(r'href="([^"]*)"', re.IGNORECASE)

    for comment in comments:
        js_files = js_pattern.findall(comment)
        data['js_files'].extend([urljoin(base_url, file) for file in js_files])
        data['emails'].extend(email_pattern.findall(comment))
        admin_paths = admin_url_pattern.findall(comment)
        data['admin_urls'].extend([urljoin(base_url, path) for path in admin_paths if 'admin' in path])

    return data

def main():
    args = parse_arguments()
    html_content = fetch_html(args.url)
    
    if html_content:
        comments = find_comments(html_content)
        sensitive_data = extract_sensitive_data(comments, args.url)
        
        print("Data Found:\n")
        for key, items in sensitive_data.items():
            if items:
                print(f"{key.capitalize()} Found:")
                for item in items:
                    print(f" - {item}")
                print("\n")  # Add a newline for better separation between sections
            else:
                print(f"No {key} found.\n")

if __name__ == '__main__':
    main()
