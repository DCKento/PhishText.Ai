import vt
import sys
import time

def main():
    # The URL to analyze is taken from the first argument to the script
    url_to_analyze = sys.argv[1]

    # Instantiate the client with your API key
    client = vt.Client('YOUR_API_KEY_HERE')

    try:
        # Scan the URL
        analysis = client.scan_url(url_to_analyze)

        # Wait until the analysis is done
        while True:
            analysis = client.get_object(f"/analyses/{analysis.id}")
            if analysis.status == "completed":
                break
            time.sleep(30)

        # Get information about the URL
        url_id = vt.url_id(url_to_analyze)
        url = client.get_object(f"/urls/{url_id}")

        # Print the number of times the URL was submitted and the last analysis stats
        print(f"Times submitted: {url.times_submitted}")
        print(f"Last analysis stats: {url.last_analysis_stats}")

    finally:
        # Close the client
        client.close()

if __name__ == "__main__":
    main()