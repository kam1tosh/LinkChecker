from flask import Flask, render_template, request
import validators
import requests
import logging
from bs4 import BeautifulSoup
import re
from requests.exceptions import ConnectionError, Timeout, TooManyRedirects, RequestException

app = Flask(__name__)


def validate_url(url):
    return validators.url(url)


def make_request(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.text
    except ConnectionError:
        logging.error(f"Connection failed for URL: {url}")
        return "Connection error: Could not connect to the URL."
    except Timeout:
        logging.error(f"Request timed out for URL: {url}")
        return "Timeout error: Server took too long to respond."
    except TooManyRedirects:
        logging.error(f"Too many redirects for URL: {url}")
        return "Error: Too many redirects."
    except RequestException as e:
        logging.error(f"Request failed for URL: {url}, Error: {str(e)}")
        return f"Request error: {str(e)}"
    except Exception as e:
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


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/courses')
def courses():
    return render_template('courses.html')


@app.route('/profile')
def profile():
    return render_template("profile.html")


@app.route('/tools', methods=['GET', 'POST'])
def tool():
    report = None
    if request.method == 'POST':
        url = request.form['url']
        report = []

        # Validate URL
        if not validate_url(url):
            report.append("Invalid URL")
        else:
            report.append("Valid URL")

            # Make Request
            response = make_request(url)
            if "error" in response.lower():
                report.append(response)
            else:
                report.append("Request successful")

                # Scan Content
                malicious, scan_report = scan_content(url)
                if malicious:
                    report.append(scan_report)
                else:
                    report.append(scan_report)

    return render_template('tools.html', report=report)


if __name__ == '__main__':
    app.run(debug=True)
