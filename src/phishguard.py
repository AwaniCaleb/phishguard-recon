from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from Levenshtein import distance as levenshtein_distance

import requests, ssdeep

class PhishGuard:
    """
    Core class for the PhishGuard Recon Tool.
    Handles fetching data, parsing HTML, and comparing site similarity.
    """
    def __init__(self):
        # Initialize the list of legitimate URLs for comparison
        self.legitimate_domains: list[str] = [
            "https://www.google.com",
            "https://www.facebook.com",
            "https://www.amazon.com",
            "https://www.twitter.com",
            "https://www.microsoft.com"
        ]
    
    def fetch_html(self, url: str) -> str | None:
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
    
    def calculate_similarity(self, s1: str, s2: str) -> int:
        """
        Calculates the Levenshtein distance between two strings (e.g., domain names).

        Args:
            s1 (str): The first string to compare.
            s2 (str): The second string to compare.

        Returns:
            int: The Levenshtein distance (number of edits).
        """
        try:
            if not s1 or not s2:
                # If a string is empty, the distance is the length of the other string
                return len(s1) + len(s2)

            # Convert to lowercase to ensure case-insensitive comparison (critical for domains)
            dist = levenshtein_distance(s1.lower(), s2.lower()) # <-- .lower() added

            return dist

        except Exception as e:
            print(f"[!] Similarity calculation failed: {e}")
            # Return a large distance on failure
            return max(len(s1) + 1, len(s2) + 1)

    def check_typo_squatting(self, target_url: str, legitimate_domains: list) -> list[str] | None:
        """
        Checks if the target URL is a potential typo-squatting of any legitimate URLs.

        Args:
            target_url (str): The suspicious URL to check.
            legitimate_domains (list): A list of known legitimate URLs.
        Returns:
            list[str]: A list of legitimate URLs that are similar to the target URL.
        """
        try:
            if not target_url or not legitimate_domains:
                raise ValueError("Target URL or legitimate URLs list is empty.")

            html_content = self.fetch_html(target_url)

            if not html_content:
                print(f"[!] Could not proceed with analysis for {target_url}.")
                return

            raw_links = self.extract_links(html_content)
            clean_links = self.analyze_links(raw_links, target_url)

            print(f"\n--- Checking {len(clean_links)} Extracted Links for Typo Squatting ---")

            suspicious_domains = set()

            for link in clean_links:
                hostname = urlparse(link).netloc

                domain = hostname.split('.')[-2] + '.' + hostname.split('.')[-1] if hostname.count('.') > 1 and hostname.split('.')[-2] != 'co' else hostname

                if domain == urlparse(target_url).netloc.split('.')[-2] + '.' + urlparse(target_url).netloc.split('.')[-1]:
                    continue

                for legit_domain in legitimate_domains:
                    legit_domain_base = legit_domain.lower().split('.')[-2] + '.' + legit_domain.lower().split('.')[-1]
                    
                    threshold = 2 if len(legit_domain_base) <= 7 else 3
                    distance = self.calculate_similarity(domain, legit_domain_base)

                    if distance > 0 and distance <= threshold:
                        warning = f"[!!! WARNING: TYPO SQUAT DETECTED !!!]\n"
                        warning += f"   - Domain on Phishing Page: {domain}\n"
                        warning += f"   - Resembles Legitimate Target: {legit_domain_base}\n"
                        warning += f"   - Levenshtein Distance: {distance}"
                        suspicious_domains.add(warning)

            if suspicious_domains:
                for warning in suspicious_domains:
                    print(warning)
            else:
                print("[+] No strong typo-squatting indicators found in extracted links.")

            
        except Exception as e:
            print(f"[!] Typo-squatting check failed: {e}")
            return []
    
    def compare_page_content(self, target_url: str, legitimate_url: str) -> bool:
        """
        Compares the HTML content of the target URL with a legitimate URL.

        Args:
            target_url (str): The suspicious URL to check.
            legitimate_url (str): The known legitimate URL to compare against.

        Returns:
            float or None: Similarity percentage between the two pages, or None on failure.
        """
        try:
            target_html = self.fetch_html(target_url)
            legit_html = self.fetch_html(legitimate_url)

            if not target_html or not legit_html:
                raise ValueError(f"[!] Could not fetch HTML for comparison between {target_url} and {legitimate_url}.")

            # Simple similarity metric: ratio of common substrings to total length
            target_set = set(target_html.split())
            legit_set = set(legit_html.split())

            common_words = target_set.intersection(legit_set)
            total_words = target_set.union(legit_set)

            similarity_percentage = (len(common_words) / len(total_words)) * 100 if total_words else 0.0

            target_hash = ssdeep.hash(target_html)
            legit_hash = ssdeep.hash(legit_html)

            score = ssdeep.compare(target_hash, legit_hash)

            if score > 50:
                print(f"[!!! WARNING: HIGH CONTENT SIMILARITY DETECTED !!!]")
                print(f"   - Target URL: {target_url}")
                print(f"   - Legitimate URL: {legitimate_url}")
                print(f"   - SSDEEP Similarity Score: {score}")
                print(f"   - Word-based Similarity Percentage: {similarity_percentage:.2f}%")

            return True

        except Exception as e:
            print(f"[!] Page content comparison failed: {e}")
            return False
    
    def run_analysis(self, target_url: str):
        """
        Runs the full analysis on the target URL, including typo-squatting and content comparison.

        Args:
            target_url (str): The suspicious URL to analyze.
        """
        print(f"\n=== Starting Analysis for {target_url} ===")

        self.check_typo_squatting(target_url, self.legitimate_domains)

        print("\n--- Starting Content Similarity Check ---")
        for legit_url in self.legitimate_domains:
            self.compare_page_content(target_url, legit_url)

        print(f"=== Analysis Completed for {target_url} ===\n")

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