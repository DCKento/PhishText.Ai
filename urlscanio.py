import requests
import json
import time

def submit_scan(api_key, url_to_scan):
    headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
    data = {"url": url_to_scan, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
    
    if response.status_code == 200:
        return response.json()['uuid']
    else:
        print(f"Failed to submit scan. Status code: {response.status_code}, Response: {response.text}")
        return None

def get_scan_results(api_key, scan_id):
    headers = {'API-Key': api_key}
    url = f"https://urlscan.io/api/v1/result/{scan_id}/"

    # As per the API's documentation, it's a good practice to wait at least 10 seconds before starting to poll
    time.sleep(10)

    while True:
        response = requests.get(url, headers=headers)

        # If the scan is not ready yet, the API will return a HTTP 404 status code
        if response.status_code != 200:
            print("Scan not ready yet. Waiting for 2 seconds before retrying...")
            time.sleep(2)
            continue

        return response.json()

api_key = "INSERT_API_KEY_HERE"
url_to_scan = "INSERT_URL_HERE"

# Submit a new scan
scan_id = submit_scan(api_key, url_to_scan)

if scan_id:
    # If the scan was submitted successfully, get the results
    results = get_scan_results(api_key, scan_id)
    print(results)
else:
    print("Failed to submit scan.")
