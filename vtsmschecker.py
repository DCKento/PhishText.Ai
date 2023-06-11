import argparse
import re
import urllib.parse
import vt
import time

def extract_url(sms_text):
    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', sms_text)
    return urls

def analyze_url(url, client):
    url_id = vt.url_id(url)
    analysis = client.scan_url(url)
    while True:
        analysis = client.get_object("/analyses/{}", analysis.id)
        if analysis.status == "completed":
            break
        time.sleep(30)
    url = client.get_object("/urls/{}", url_id)
    print(f"URL: {url}")
    print(f"Times submitted: {url.times_submitted}")
    print(f"Last analysis stats: {url.last_analysis_stats}")
    print(f"Reputation: {url.reputation}")
    print(f"Categories: {url.categories}")

def main():
    parser = argparse.ArgumentParser(description='Analyze URLs in a SMS message using VirusTotal.')
    parser.add_argument('sms', help='The SMS message text.')
    args = parser.parse_args()

    client = vt.Client("API_KEY_HERE")
    urls = extract_url(args.sms)

    for url in urls:
        analyze_url(url, client)

    client.close()

if __name__ == "__main__":
    main()