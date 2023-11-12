import argparse
import re
import urllib.parse
import vt   # Import the VirusTotal module
import time
import openai  # Import the OpenAI module
import requests
import json
from flask import Flask, request, render_template
from OTXv2 import OTXv2 # Import the OTX module
import get_malicious

# Function to extract URLs from the SMS message. Uses regex and returns the URL
def extract_url(sms_text):
    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', sms_text)
    return urls

# Function to analyze a URL using VirusTotal
def analyze_url(url, client):
    url_id = vt.url_id(url)
    analysis = client.scan_url(url)
    while True:
        analysis = client.get_object("/analyses/{}", analysis.id)
        if analysis.status == "completed":
            break
        time.sleep(30)
    url = client.get_object("/urls/{}", url_id)

    # Store the results as a string. Results obtained are based on the output of the VT analysis
    result_str = f"URL: {url}\nTimes submitted: {url.times_submitted}\nLast analysis stats: {url.last_analysis_stats}\nReputation: {url.reputation}\nCategories: {url.categories}"
    return result_str

# Function to submit a URL for scanning on URLScan.io
def submit_scan(api_key, url_to_scan):
    headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
    data = {"url": url_to_scan, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
    
    if response.status_code == 200:
        return response.json()['uuid']
    else:
        return None

# Function to retrieve the scan results from URLScan.io
def get_scan_results(api_key, scan_id):
    headers = {'API-Key': api_key}
    url = f"https://urlscan.io/api/v1/result/{scan_id}/"
    time.sleep(10)
    while True:
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            time.sleep(4)
            continue
        return response.json()

# Function to check with OTX
def check_with_alien_vault(url):
    API_KEY = 'OTX_API_KEY'
    OTX_SERVER = 'https://otx.alienvault.com/'
    otx = OTXv2(API_KEY, server=OTX_SERVER)

    try:
        alerts = get_malicious.url(otx, url)
        if alerts:
            return f"Identified as potentially malicious: {json.dumps(alerts)}"
        else:
            return 'Unknown or not identified as malicious'
    except Exception as e:
        return f"Error checking URL with AlienVault OTX: {str(e)}"

# Function to chat with the GPT-4-turbo model
def chat_with_gpt(sms_text, vt_analysis_result, urlscan_analysis_result, alien_vault_result):
    openai.api_key = 'OPENAI_API_KEY'
    messages = [
        {"role": "system", "content": "You are an intelligent assistant that specializes in cybersecurity and the identification and analysis of phishing SMS messages."},
        {"role": "user", "content": f"Analyze this SMS message: '{sms_text}' and its VirusTotal analysis: '{vt_analysis_result}' and URLScan.io analysis: '{urlscan_analysis_result}' AlienVault OTX analysis: '{alien_vault_result}' to determine if this is a phishing attempt. Give your reasoning for why this is or is not a phishing SMS"},
    ]
    
    model = 'gpt-3.5-turbo'
    response = openai.ChatCompletion.create(model=model, messages=messages)

    # Return the assistant's reply
    return response['choices'][0]['message']['content']

# Main function. Parses the arguments, creates a VT client and loops through the URL's.
def main(sms):
    client = vt.Client("VT_API_KEY")
    urls = extract_url(sms)

    results = []
    for url in urls:
        vt_analysis_result = analyze_url(url, client)
        urlscan_api_key = "URLSCAN_API_KEY"
        scan_id = submit_scan(urlscan_api_key, url)
        urlscan_analysis_result = None
        alien_vault_result = check_with_alien_vault(url)
        if scan_id:
            urlscan_analysis_result = get_scan_results(urlscan_api_key, scan_id)
        chat_gpt_result = chat_with_gpt(sms, vt_analysis_result, urlscan_analysis_result, alien_vault_result)
        results.append(chat_gpt_result)

    client.close()

    if not results:
        print("No results generated. Check individual processing steps.")
    else:
        print(f"Results generated: {results}")

    return results

# Create the Flask application
app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        sms_text = request.form.get('sms')
        results = main(sms_text)
        results_str = "\n".join(results)
        
        # Add a log to check what's being passed to the template
        print(f"Passing to template: {results_str}")

        return render_template('results.html', results_str=results_str)

    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True)
