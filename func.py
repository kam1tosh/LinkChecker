from bs4 import BeautifulSoup
import requests, logging, re, validators
from requests.exceptions import ConnectionError, Timeout, TooManyRedirects, RequestException


def is_valid_url(url):
    return validators.url(url)


def make_request(url):
    try:
        # Attempt to make a GET request to the provided URL with a timeout of 5 seconds
        response = requests.get(url, timeout=5)
        # Raise an HTTPError if the HTTP request returned an unsuccessful status code
        response.raise_for_status()
        return response.text
    except ConnectionError:
        # Log an error if there was a connection error
        logging.error(f"Connection failed for URL: {url}")
        return "Connection error: Could not connect to the URL."
    except Timeout:
        # Log an error if the request timed out
        logging.error(f"Request timed out for URL: {url}")
        return "Timeout error: Server took too long to respond."
    except TooManyRedirects:
        # Log an error if there were too many redirects
        logging.error(f"Too many redirects for URL: {url}")
        return "Error: Too many redirects."
    except RequestException as e:
        # Log an error if there was a generic request exception
        logging.error(f"Request failed for URL: {url}, Error: {str(e)}")
        return f"Request error: {str(e)}"
    except Exception as e:
        # Log an error if there was any other unexpected exception
        logging.error(f"Unexpected error for URL: {url}, Error: {str(e)}")
        return f"Unexpected error: {str(e)}"


def scan_content(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return False, "Error loading page"

        soup = BeautifulSoup(response.content, 'html.parser')

        # Check scripts for malicious patterns
        scripts = soup.find_all('script')
        script_patterns = ['eval\\(', 'document.write', 'unescape', '.src\\s*=', 'window.location', 'base64']
        for script in scripts:
            if any(re.search(pattern, script.text) for pattern in script_patterns):
                return True, "Suspicious script detected"

        # Check iframes for hidden iframes or suspicious sources
        iframes = soup.find_all('iframe')
        for iframe in iframes:
            if "display:none" in iframe.get('style', '') or re.search('position:\\s*absolute;',
                                                                      iframe.get('style', '')):
                return True, "Hidden iframe detected"
            if "example.com" not in iframe.get('src', ''):
                return True, "Suspicious iframe source detected"

        # Check links for phishing attempts
        links = soup.find_all('a')
        for link in links:
            href = link.get('href', '')
            if "login" in href or "verify" in href:
                return True, "Possible phishing link detected"

        # Check for auto-redirects in meta tags
        meta_redirects = soup.find_all('meta')
        for meta in meta_redirects:
            if 'http-equiv' in meta.attrs and meta['http-equiv'].lower() == "refresh":
                if "url" in meta['content'].lower():
                    return True, "Meta refresh redirect detected"

    except requests.RequestException as e:
        return False, f"Failed to retrieve content: {str(e)}"

    return False, "No malicious content detected."
