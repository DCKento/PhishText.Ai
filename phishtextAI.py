import argparse
import re
import urllib.parse
import vt   # Import the VirusTotal module
import time
import openai  # Import the OpenAI module

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

# Function to chat with the GPT-3.5-turbo model
def chat_with_gpt(sms_text, analysis_result):
    # Set up the API key and create a prompt message. Uses the 'system' and 'user' roles as the base prompt and adds the SMS message along with the results from the VT analysis to form the prompt message.
    openai.api_key = 'YOUR_OPENAI_API_KEY'
    messages = [
        {"role": "system", "content": "You are an intelligent assistant that specializes in cybersecurity and the identification and analysis of phishing SMS messages."},
        {"role": "user", "content": f"Analyze this SMS message: '{sms_text}' and its VirusTotal analysis: '{analysis_result}' to determine if this is a phishing attempt. Give your reasoning for why this is or is not a phishing SMS"},
    ]
    
    model = 'gpt-3.5-turbo'
    response = openai.ChatCompletion.create(model=model, messages=messages)

    # Return the assistant's reply
    return response['choices'][0]['message']['content']

# Main function. Parses the argumennts, creates a VT client and loops through the URL's.
def main():
    parser = argparse.ArgumentParser(description='Analyze URLs in a SMS message using VirusTotal.')
    parser.add_argument('sms', help='The SMS message text.')
    args = parser.parse_args()

    client = vt.Client("YOUR_VT_API_KEY")
    urls = extract_url(args.sms)

    for url in urls:
        analysis_result = analyze_url(url, client)
        chat_gpt_result = chat_with_gpt(args.sms, analysis_result)
        print(chat_gpt_result)

    client.close()

if __name__ == "__main__":
    main()