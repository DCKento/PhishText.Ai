# PhishText.AI - AI SMS Phishing Analysis Tool

PhishText.AI is a tool built in Python that aims to identify potential phishing attempts in SMS messages. It uses a combination of AI language evaluation and web security checks to evaluate the contents and URL in a SMS message to determine if it is a phishing attempt or nnot.

The tool uses two main steps to analyze SMS messages:

URL Check: The tool first looks for any URLs in the SMS. If a URL is found, it's checked using the VirusTotal API, which can indicate if the URL is known to be unsafe.

Text Analysis: The tool uses the ChatGPT API from OpenAI to analyze the overall text of the SMS. This can help determine if the SMS text matches patterns often found in phishing messages.

By using these methods, PhishText.AI can provide an indication if an SMS might be a phishing attempt. This can help users avoid falling for scams that might lead to them giving away personal information. The tool is intended as a practical demonstration of how AI can be used to improve security.

# AI SMS Phishing Detection Tool High Level Plan

## Step 1: URL Extraction
Develop a function or mechanism to identify and extract URLs from the given SMS text. Use regular expressions or libraries like `urllib` in Python to achieve this.

## Step 2: VirusTotal API Integration
Write a function that uses the VirusTotal API to check whether a given URL is malicious. The function should input a URL and output a response that contains details of the analysis performed.

API reference:
https://developers.virustotal.com/reference/scan-url

vt-py python module reference:
https://virustotal.github.io/vt-py/quickstart.html
https://github.com/VirusTotal/vt-py

Example input:

```
python .\vturlchecker.py https://web.nz-t.cyou/
```

Example output:

```
Times submitted: 4
Last analysis stats: {'harmless': 66, 'malicious': 5, 'suspicious': 1, 'undetected': 17, 'timeout': 0}
Reputation: 0
Categories: {'Forcepoint ThreatSeeker': 'newly registered websites', 'Webroot': 'Phishing and Other Frauds', 'alphaMountain.ai': 'Suspicious (alphaMountain.ai)'}
```

![image](https://github.com/DCKento/PhishText.AI/assets/20635370/0b6ac1fe-833f-4ef7-9334-7ad3e3f17cd8)

Together with URL extraction from step 1:

![image](https://github.com/DCKento/PhishText.AI/assets/20635370/54a5af24-7dd0-474e-add7-5bc21d8cfb89)

This allows for the entire SMS message to be passed as an argument, with the URL being extracted and analyzed via the VirusTotal API.

## Step 3: ChatGPT API Integration
Set up a method to connect and interact with the ChatGPT API. The function should generate a prompt based on the input SMS text and call the ChatGPT API to get a response.

## Step 4: Response Analysis and Phishing Detection Function
Develop a function to interpret the response from the GPT API. Since GPT returns a text response,  define some rules or use text analysis techniques to determine whether it's indicating the message could be phishing. Alternatively, include in the ChatGPT response for it to return a clear string value (True or False) to use as the response indicator. ChatGPT output could even directly specify whether the SMS is phishing or not, through its analysis of the text and VirusTotal output.

Combine all the above steps into the Python program which will extract URLs from the input SMS text, check each URL with VirusTotal, call the GPT API to analyze the text, and return output that will suggest whether or not the SMS text appears to be phishing.

Example input:

```
python .\phishtextai.py "NZTA-Your tolls are not yet paid and are about to be overdue.please click to view and pay: https://web.nz-t.cyou"
```

Example output:

```
Based on the given SMS message and the VirusTotal analysis, it is highly likely that this is a phishing attempt.

The SMS message is designed to create a sense of urgency and fear by indicating that the recipient's tolls are about to be overdue. It requests the recipient to click on a link to view and pay their tolls. However, the link provided in the message directs to a suspicious domain "https://web.nz-t.cyou" which is not a legitimate domain for the New Zealand Transport Agency (NZTA).

The VirusTotal analysis also indicates that the URL has been submitted eight times and flagged as "malicious" and "phishing and fraud" by Sophos and "Phishing and Other Frauds" by Webroot. The URL has also been categorized as a "newly registered website" by Forcepoint ThreatSeeker and as "Suspicious" by alphaMountain.ai.

Therefore, it is highly recommended not to click on the link provided in the message and to delete it immediately to avoid any potential phishing attacks or scams. It is always safer to directly visit the legitimate website or call the official customer support number to inquire about the status of your tolls.
```

![image](https://github.com/DCKento/PhishText.AI/assets/20635370/44f7260b-3242-416e-a514-d2727b164ad6)


## Step 6: Testing
Test the function with a variety of SMS messages, both phishing and non-phishing. Use these tests to debug and improve the function. Also, consider edge cases or uncommon scenarios and see how the function handles them.

## Step 7: Iteration
After the initial testing, continue to iterate and improve the function based on additional feedback and testing.

# Pseudocode

```python
function is_phishing_sms(sms_text):
    # Initialize phishing flag to False
    is_phishing = False
    
    # Step 1: Check for URLs in sms_text
    urls = extract_urls(sms_text)
    
    # Step 2: Check each URL with VirusTotal API
    for url in urls:
        if check_url_with_virustotal(url) is malicious:
            is_phishing = True

    # Step 3: Always use GPT API to analyze text
    gpt_prompt = f"Is the following SMS potentially phishing or harmful: '{sms_text}'?"
    gpt_response = call_gpt_api(gpt_prompt)

    # Step 4: Based on GPT response, update whether text is phishing or not
    if gpt_response indicates phishing:
        is_phishing = True

    return is_phishing
```
