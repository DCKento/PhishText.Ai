import argparse
import vt

def scan_url(api_key, url):
    client = vt.Client(api_key)
    analysis = client.scan_url(url)
    client.close()
    return analysis

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Scan a URL using the VirusTotal API.')
    parser.add_argument('url', help='The URL to scan.')
    args = parser.parse_args()

    api_key = '<apikey>'  # Replace '<apikey>' with your actual VirusTotal API key
    analysis = scan_url(api_key, args.url)
    print(analysis)
