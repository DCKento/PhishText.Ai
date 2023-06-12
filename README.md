# PhishText.AI - SMS Phishing Analysis using OpenAI and VirusTotal

PhishText.AI is a tool built in Python that aims to identify potential phishing attempts in SMS messages. It uses a combination of AI language evaluation and web security checks to evaluate the contents and URLs in a SMS message to determine if the SMS is a phishing attempt.

The tool uses two main steps to analyze SMS messages:

1. URL Check: The tool first looks for any URLs in the SMS. If a URL is found, it is extracted and annalyzed using the VirusTotal API, which can provide various indicators to help determine if the URL is known to be unsafe.
2. Text Analysis: The tool uses the ChatGPT API from OpenAI to analyze the overall text of the SMS and the analysis output from VirusTotal. ChatGPT will then provide a final analysis on whether the SMS could be a phishing attempt.

By using these methods, PhishText.AI can provide an indication if an SMS might be a phishing attempt. This can help users avoid falling for scams that might lead to them giving away personal information. The tool is intended as a practical demonstration of how AI can be used to improve security.

![image](https://github.com/DCKento/PhishText.AI/assets/20635370/c0ca3f18-9123-48f8-b9af-bf118b7eacb5)

# Implementation Details

## Command Line Interface

The program accepts an SMS message as a command-line argument. This design makes the program flexible and easy to integrate with other systems. Future releases will develop a web-interface where SMS messages can be copy and pasted for more convenient analysis.

## URL Extraction
Uses regular expressions to identify and extract URLs from the given SMS text.

Current regex implementation:

```
re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
```

## VirusTotal API Integration and Analysis
Phistext.AI uses the VirusTotal API to check whether an extracted URL is malicious. The function inputs a URL and outputs a response that contains details of the analysis performed.

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

This allows for the entire SMS message to be passed as an argument, with the URL being extracted and analyzed via the VirusTotal API. Once completed, it retrieves the URL's details such as submission times, last analysis stats, reputation, and categories from VirusTotal.

## ChatGPT API Integration
Using the OpenAI Python module and OpenAI API, Phishtext.AI connects and interacts with ChatGPT. The function generates a prompt based on the input SMS text along with the VirusTotal analysis and calls the ChatGPT API to get a response.

## Response Analysis and Phishing Detection Function
Phishtext.AI then uses the OpenAI GPT-3.5-turbo model to provide a human-like assessment of whether the SMS might be a phishing attempt. It takes the SMS text and VirusTotal analysis result as input, and asks the model to provide an analysis. Since ChatGPT returns a text response, the ChatGPT output can directly specify whether the SMS is phishing or not through its analysis of the text and VirusTotal output.

With the above steps combined, Phishtext.AI will: 

* extract URLs from the input SMS text
* check each URL with VirusTotal
* call the ChatGPT API to analyze the text
* return output that will suggest whether or not the SMS text appears to be phishing

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

ChatGPT is able to analyze the language used in the SMS message, the URL itself with the added context from the VirusTotal analysis to determine that the SMS is a phishing attempt. ChatGPT is even able to provide some recommendations for next steps and safeguarding techniques.

## Future Steps: Further Testing
Test the function with a variety of SMS messages, both phishing and non-phishing. Use these tests to debug and improve the program. Also, consider edge cases or uncommon scenarios and see how the program handles them.

## Future Steps: Iteration
After the initial testing, continue to iterate and improve the program based on additional feedback and testing.

# Prerequisites and Dependencies

Phishtext.AI requires the following Python libraries:
* argparse
* re
* urllib.parse
* vt
* openai

Phishtext.AI requires the following API keys:
* VirusTotal API key: https://support.virustotal.com/hc/en-us/articles/115002088769-Please-give-me-an-API-key
* OpenAI API key: https://help.openai.com/en/articles/4936850-where-do-i-find-my-secret-api-key

Be mindful of rate limits and charges that may apply to the use of these API's.

# Limitations and Risks

* The accuracy of the solution depends on the effectiveness of the GPT-3.5-turbo model in detecting phishing attempts and the reliability of the VirusTotal API.
* Overuse may result in hitting rate limits or large financial charge for both OpenAI and VirusTotal APIs.
* Phishtext.AI may not correctly interpret URLs that do not match the regular expression used for URL extraction.
* The model can potentially output false positives or negatives.
* The OpenAI API key and the VirusTotal API key are hardcoded, posing a potential security risk if the code is publicly exposed.

# Future Enhancements

* Upgrade to the ChatGPT 4.0 model once API access is made available.
* Add a web-interface that is compatible with both mobile and desktop interfaces for easier submission of SMS messages.
* Improve URL extraction mechanism to cover a wider range of URL formats.
* Add more sophisticated natural language processing to analyze the textual content of the SMS.
* Use a secure method to handle sensitive information such as API keys.
* Implement mechanisms to handle API rate limiting.
* Add error handling for network failures and other exceptions.

# Pseudocode

```
START

IMPORT necessary libraries

FUNCTION extract_url(sms_text):
    FIND urls in sms_text using regex
    RETURN urls

FUNCTION analyze_url(url, client):
    CALCULATE url_id from url
    BEGIN scanning url using client
    LOOP UNTIL scan is complete
        CHECK status of scan
        WAIT 30 seconds before checking again
    GET url details from VirusTotal
    COMPOSE result string with url details
    RETURN result string

FUNCTION chat_with_gpt(sms_text, analysis_result):
    SET API key
    PREPARE chat messages for GPT model
    CREATE a chat completion request with GPT model
    GET assistant's reply from the response
    RETURN reply

FUNCTION main:
    PREPARE argument parser
    PARSE arguments
    CREATE VirusTotal client
    EXTRACT urls from SMS text
    FOR EACH url DO
        ANALYZE url using VirusTotal
        GET analysis from GPT model
        PRINT analysis result
    CLOSE VirusTotal client

RUN main function

END
```
