"""
Academic Research Web Crawler for Web Security Classes.

This script is provided solely for academic research and educational purposes.
It enables students to experiment with research-focused web crawling techniques,
parse desired product information, and send notifications (e.g., via Slack).

Disclaimer:
    Use this tool responsibly and in compliance with all applicable laws.
    The author does not assume any responsibility for any misuse of this software.
"""

import time
import random
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import pytz

# =============================================================================
# Configuration
# =============================================================================

LAST_PROXY_REFRESH = 0       # Timestamp of the last proxy refresh
VALID_PROXIES = []           # List of valid proxies for reuse
MUTE_NOTIFICATIONS = {}      # Dict to store last notification timestamp for each item
MUTE_DURATION = 10800        # Mute duration in seconds (3 hours)

# User-Agent strings for HTTP requests
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1 Safari/605.1.15",
    "Mozilla/5.0 (iPad; CPU OS 14_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 9; ONEPLUS A6000) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.152 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; ARM64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
    "Mozilla/5.0 (Linux; U; Android 8.0.0; en-us; Nexus 5 Build/OPR6.170623.017) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.98 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Linux; Android 11; SM-N975U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1 Safari/605.1.15"
]

TARGET_KEYWORDS = []         # List of keywords to filter desired products (case-insensitive)
NORMAL_WAIT = 300            # Wait time in seconds (5 minutes) outside peak hours
PEAK_WAIT_MIN = 1            # Minimum wait time in seconds during peak hours
PEAK_WAIT_MAX = 5            # Maximum wait time in seconds during peak hours

ROOT_URL = ""                # Base URL of the website to research (insert URL here)
SLACK_WEBHOOK_URL = ""       # Slack Webhook URL for sending notifications (insert URL here)

# =============================================================================
# Helper Functions
# =============================================================================

def within_peak_hours():
    """
    Check if the current time in EST (US/Western) is within peak hours (9 AM to 6 PM).

    Returns:
        bool: True if within peak hours, False otherwise.
    """
    utc_tz = pytz.utc
    est_tz = pytz.timezone('US/Western')  # Adjust as necessary for your locale
    now_utc = datetime.now(utc_tz)
    now_est = now_utc.astimezone(est_tz)
    return 9 <= now_est.hour < 18

def test_proxy(proxy, timeout=3):
    """
    Test if the provided proxy works by making a request to a test URL.

    Args:
        proxy (str): Proxy address in "IP:PORT" format.
        timeout (int, optional): Timeout duration in seconds. Defaults to 3.

    Returns:
        bool: True if the proxy works, False otherwise.
    """
    test_url = "https://httpbin.org/ip"
    try:
        response = requests.get(test_url, proxies={"http": proxy, "https": proxy}, timeout=timeout)
        return response.status_code == 200
    except Exception:
        return False

def is_recently_checked(last_checked):
    """
    Determine if the proxy was checked within the last 30 minutes.

    Args:
        last_checked (str): Time string from the proxy list (e.g., "9 secs ago", "3 mins ago").

    Returns:
        bool: True if checked within 30 minutes, False otherwise.
    """
    if "sec" in last_checked:
        return True  # Proxies checked seconds ago are considered valid
    elif "min" in last_checked:
        try:
            minutes = int(last_checked.split()[0])
            return minutes <= 30
        except ValueError:
            return False  # Unexpected format
    return False

def fetch_free_proxies():
    """
    Fetch a list of free proxies from an online source.

    Returns:
        list: A list of valid proxies.
    """
    # The URL below is used to fetch free proxies.
    proxy_url = "https://www.sslproxies.org/"  # Replace with a reliable source if needed
    try:
        response = requests.get(proxy_url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        table = soup.find("table", {"class": "table table-striped table-bordered"})
        if not table:
            print("Proxy table not found.")
            return []

        valid_proxies = []
        rows = table.find("tbody").find_all("tr")
        for row in rows:
            cols = row.find_all("td")
            if len(cols) >= 8:
                ip = cols[0].text.strip()
                port = cols[1].text.strip()
                proxy = f"{ip}:{port}"
                https_support = cols[6].text.strip().lower()  # Check HTTPS support
                last_checked = cols[7].text.strip().lower()     # Check recency of proxy check
                if https_support == "yes" and is_recently_checked(last_checked) and test_proxy(proxy):
                    valid_proxies.append(proxy)

        print(f"Fetched {len(valid_proxies)} working proxies.")
        return valid_proxies
    except Exception as e:
        print(f"Error fetching proxy list: {e}")
        return []

def fetch_product_page(url, proxies):
    """
    Fetch a product page using available proxies; fallback to direct request if necessary.

    Args:
        url (str): URL of the product page.
        proxies (list): List of proxy addresses.

    Returns:
        BeautifulSoup or None: Parsed HTML content or None if fetching fails.
    """
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://www.google.com",  # Reference header
        "Connection": "keep-alive",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    }
    while proxies:
        proxy = random.choice(proxies)
        try:
            response = requests.get(url, headers=headers, proxies={"http": proxy, "https": proxy}, timeout=10)
            response.raise_for_status()
            print(f"Successfully fetched data using proxy: {proxy}")
            return BeautifulSoup(response.text, "html.parser")
        except Exception as e:
            print(f"Proxy {proxy} failed: {e}. Removing it from the list.")
            proxies.remove(proxy)

    # Fallback: Make a direct request without proxy
    print("No working proxies left. Falling back to direct request.")
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        print("Successfully fetched data without proxy.")
        return BeautifulSoup(response.text, "html.parser")
    except Exception as e:
        print(f"Failed to fetch data without proxy: {e}")
        return None

def parse_for_desired_products(soup):
    """
    Parse HTML content for product items matching target keywords.

    Args:
        soup (BeautifulSoup): Parsed HTML content.

    Returns:
        list: List of product titles that match the target keywords.
    """
    found_items = []
    all_items = []

    product_divs = soup.find_all("div", class_="product-item")
    for product_div in product_divs:
        link_tag = product_div.find("a", title=True)
        if link_tag:
            product_title = link_tag["title"]
            all_items.append(product_title)
            if any(keyword.lower() in product_title.lower() for keyword in TARGET_KEYWORDS):
                found_items.append(product_title)

    print("All crawled items:", all_items)
    return found_items

def send_slack_notification(message):
    """
    Send a notification message to Slack via a webhook.

    Args:
        message (str): The notification message.
    """
    payload = {"text": message}
    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        response.raise_for_status()
        print("Slack notification sent successfully.")
    except Exception as e:
        print(f"Failed to send Slack notification: {e}")

def refresh_proxies():
    """
    Refresh the global list of valid proxies if the refresh interval has passed.
    """
    global LAST_PROXY_REFRESH, VALID_PROXIES
    current_time = time.time()
    # Refresh proxies if more than 3000 seconds (~50 minutes) have elapsed
    if current_time - LAST_PROXY_REFRESH >= 3000:
        print("Refreshing proxies...")
        VALID_PROXIES = fetch_free_proxies()
        LAST_PROXY_REFRESH = current_time

# =============================================================================
# Main Function
# =============================================================================

def main():
    """
    Main function to execute the web crawling loop.
    """
    global VALID_PROXIES, MUTE_NOTIFICATIONS

    while True:
        refresh_proxies()  # Refresh proxies if needed

        soup = fetch_product_page(ROOT_URL, VALID_PROXIES)
        if soup:
            found_items = parse_for_desired_products(soup)
            current_time = time.time()

            for item in found_items:
                # Skip notification if item was recently notified (mute period)
                if item in MUTE_NOTIFICATIONS and (current_time - MUTE_NOTIFICATIONS[item]) < MUTE_DURATION:
                    print(f"Item '{item}' is muted. No notification sent.")
                    continue

                notification_message = f"Matched item found: {item}"
                send_slack_notification(notification_message)
                MUTE_NOTIFICATIONS[item] = current_time
                print(f"Notification sent for item: {item}")
        else:
            print("No desired items found.")

        # Determine wait time based on peak hours
        wait_time = random.randint(PEAK_WAIT_MIN, PEAK_WAIT_MAX) if within_peak_hours() else NORMAL_WAIT
        # Add a small random delay to avoid predictable patterns
        time.sleep(wait_time + random.uniform(0.5, 5.0))

if __name__ == "__main__":
    main()
