from bs4 import BeautifulSoup
from urllib.parse import urljoin

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
    
    def analyze_links(self, links: list, base_url: str) -> list[str]:
        """
        Filters and normalizes extracted links, converting relative URLs to absolute ones.

        Args:
            links (list): A list of URLs extracted from HTML content.
            base_url (str): The base URL of the site being analyzed.
        
        Returns:
            list[str]: A list of clean, absolute, and unique URLs.
        """
        if not links:
            return []
        
        # Automatically ensure links are unique
        clean_links = set()
        
        for link in links:
            # Filter out non-http links
            if link.startswith(('#', 'mailto:', 'javascript:', 'tel:')):
                continue

            # Relative links to absolute using urljoin
            absolute_link = urljoin(base_url, link)

            # Add link to the set
            clean_links.add(absolute_link)

        return list(clean_links)

if __name__ == "__main__":
    url = "https://google.com"

    phish_tool = PhishGuard()

    print("\n--- Testing Valid URL ---")
    html_content = phish_tool.fetch_html(url)
    if html_content:
        print(f"[+] Successfully fetched {len(html_content)} bytes of HTML.")

        raw_links = phish_tool.extract_links(html_content)

        print(f"[+] Extracted {len(raw_links)} raw links.")

        links = phish_tool.analyze_links(raw_links, url) 
    
        print(f"[+] Extracted {len(links)} unique, clean links:")
        
        for link in links:
            print(f"    - {link}")