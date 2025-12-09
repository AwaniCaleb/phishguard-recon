from bs4 import BeautifulSoup

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
        
    def extract_links(self, html_content: str) -> list:
        """
        Parses HTML content to extract all URLs from <a> tags.

        Args:
            html_content (str): The raw HTML content string.

        Returns:
            list[str]: A list of all unique URLs found in the 'href' attributes.
        """
        try:
            if not html_content:
                raise ValueError("The HTML content provided is empty.")
            
            # Initialize Beautiful Soup object
            soup = BeautifulSoup(html_content, 'lxml')

            # Find all <a> tags
            all_a_tags = soup.find_all('a')

            # Extract href attributes and ensure uniqueness
            links = {
                tag.get('href') for tag in all_a_tags if tag.get('href')
            }

            return list(links)
        except Exception as e:
            print(f"[!] {e}")
            return []

if __name__ == "__main__":
    phish_tool = PhishGuard()

    print("\n--- Testing Valid URL ---")
    html_content = phish_tool.fetch_html("https://google.com")
    if html_content:
        print(f"[+] Successfully fetched {len(html_content)} bytes of HTML.")

        links = phish_tool.extract_links(html_content)
        print(f"[+] Extracted {len(links)} unique links:")
        
        for link in links:
            print(f"    - {link}")