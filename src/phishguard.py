import requests

class PhishGuard:
    """
    Core class for the PhishGuard Recon Tool.
    Handles fetching data, parsing HTML, and comparing site similarity.
    """
    def __init__(self):
        pass
    
    def fetch_html(self, url: str) -> str or None:
        """
        Fetches the HTML content from a given URL.

        Args:
            url (str): The suspicious or legitimate URL to check.

        Returns:
            str or None: The HTML content as a string if successful, otherwise None.
        """
        try:
            if not url:
                raise ValueError("The URL provided is empty.")

            response = requests.get(url, timeout=10)
            
            # Raise an HTTPError for bad responses
            response.raise_for_status()

            return response.text
            
        # Catch request-related errors
        except requests.RequestException as e:
            print(f"[!] Error fetching URL {url}: {e}")
            return None

if __name__ == "__main__":
    phish_tool = PhishGuard()

    print("\n--- Testing Valid URL ---")
    html_content = phish_tool.fetch_html("https://google.com")
    if html_content:
        print(f"[+] Successfully fetched {len(html_content)} bytes of HTML.")

    print("\n--- Testing Invalid URL ---")
    phish_tool.fetch_html("https://this-domain-does-not-exist-123456.com")