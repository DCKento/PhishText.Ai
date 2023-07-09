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

def extract_relevant_data(json_data):
    # Extract 'verdicts', 'page' and 'lists' from the input JSON data
    relevant_data = {
        'verdicts': json_data.get('verdicts', {}),
        'page': json_data.get('page', {}),
        'lists': json_data.get('lists', {})
    }
    return relevant_data

api_key = "API_KEY_HERE"
url_to_scan = "URL_TO_SCAN_HERE"

# Submit a new scan
scan_id = submit_scan(api_key, url_to_scan)

if scan_id:
    # If the scan was submitted successfully, get the results
    results = get_scan_results(api_key, scan_id)
    
    # Extract the relevant data
    extracted_data = extract_relevant_data(results)
    
    # Print the extracted data
    print(extracted_data)
else:
    print("Failed to submit scan.")
