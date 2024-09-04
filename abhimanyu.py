import argparse
import requests
import sys
import json
import os
import concurrent.futures
from datetime import datetime

BANNER = """
           ____  _    _ _____ __  __          _   ___     ___    _ 
     /\   |  _ \| |  | |_   _|  \/  |   /\   | \ | \ \   / / |  | |
    /  \  | |_) | |__| | | | | \  / |  /  \  |  \| |\ \_/ /| |  | |
   / /\ \ |  _ <|  __  | | | | |\/| | / /\ \ | . ` | \   / | |  | |
  / ____ \| |_) | |  | |_| |_| |  | |/ ____ \| |\  |  | |  | |__| |
 /_/    \_\____/|_|  |_|_____|_|  |_/_/    \_\_| \_|  |_|   \____/ 
 f   e   t   c   h   U   R   L   o   f   w   e   b   s   i   t   e   s             
                                                                   
                                                        """

def get_wayback_urls(domain, no_subs):
    subs_wildcard = '' if no_subs else '*.'
    url = f'http://web.archive.org/cdx/search/cdx?url={subs_wildcard}{domain}/*&output=json&collapse=urlkey'
    response = requests.get(url)
    if response.status_code != 200:
        return []

    result = []
    try:
        data = json.loads(response.text)
        for entry in data[1:]:  # Skip the first entry (headers)
            date = entry[1]
            url = entry[2]
            result.append({'date': date, 'url': url})
    except (json.JSONDecodeError, IndexError):
        pass
    return result

def get_common_crawl_urls(domain, no_subs):
    subs_wildcard = '' if no_subs else '*.'
    url = f'http://index.commoncrawl.org/CC-MAIN-2018-22-index?url={subs_wildcard}{domain}/*&output=json'
    response = requests.get(url)
    if response.status_code != 200:
        return []

    result = []
    try:
        for line in response.text.splitlines():
            entry = json.loads(line)
            result.append({'date': entry['timestamp'], 'url': entry['url']})
    except (json.JSONDecodeError, KeyError):
        pass
    return result

def get_virus_total_urls(domain):
    result = []
    api_key = os.getenv('VT_API_KEY')
    if not api_key:
        return result

    url = f'https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_key}&domain={domain}'
    response = requests.get(url)
    if response.status_code != 200:
        return result

    try:
        data = response.json()
        for item in data.get('detected_urls', []):
            result.append({'url': item['url']})
    except (json.JSONDecodeError, KeyError):
        pass
    return result

def is_subdomain(url, domain):
    from urllib.parse import urlparse
    parsed_url = urlparse(url)
    return parsed_url.hostname.lower() != domain.lower()

def fetch_urls(domain, no_subs, dates):
    fetch_fns = [get_wayback_urls, get_common_crawl_urls, get_virus_total_urls]
    seen = set()
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(fn, domain, no_subs) for fn in fetch_fns[:-1]]
        futures.append(executor.submit(fetch_fns[-1], domain))

        for future in concurrent.futures.as_completed(futures):
            for w in future.result():
                if no_subs and is_subdomain(w['url'], domain):
                    continue
                if w['url'] not in seen:
                    seen.add(w['url'])
                    if dates and 'date' in w:
                        try:
                            date = datetime.strptime(w['date'], '%Y%m%d%H%M%S')
                            print(f"{date.isoformat()} {w['url']}")
                        except ValueError:
                            print(w['url'])
                    else:
                        print(w['url'])

def get_versions(url):
    result = []
    archive_url = f'http://web.archive.org/cdx/search/cdx?url={url}&output=json'
    response = requests.get(archive_url)
    if response.status_code != 200:
        return result

    try:
        data = json.loads(response.text)
        seen = set()
        for entry in data[1:]:
            digest = entry[5]
            if digest not in seen:
                seen.add(digest)
                result.append(f"https://web.archive.org/web/{entry[1]}if_/{entry[2]}")
    except (json.JSONDecodeError, IndexError):
        pass
    return result

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="Insipration waybackurl by tomnom.", 
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     epilog="Developed by Partha\n")
    parser.add_argument("domains", nargs="*", help="Domain(s) to fetch URLs for.")
    parser.add_argument("--dates", action="store_true", help="Show date of fetch in the first column.")
    parser.add_argument("--no-subs", action="store_true", help="Don't include subdomains of the target domain.")
    parser.add_argument("--get-versions", action="store_true", help="List URLs for crawled versions of input URL(s).")
    args = parser.parse_args()

    if args.domains:
        domains = args.domains
    else:
        domains = [line.strip() for line in sys.stdin]

    if args.get_versions:
        for domain in domains:
            versions = get_versions(domain)
            print("\n".join(versions))
        return

    for domain in domains:
        fetch_urls(domain, args.no_subs, args.dates)

if __name__ == "__main__":
    main()
