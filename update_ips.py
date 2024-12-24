#!/usr/bin/env python3

import sys
import os
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess
import configparser
import logging
import urllib3
from requests.auth import HTTPBasicAuth

# Determine the script's directory and default config.ini location
script_dir = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(script_dir, 'config.ini')

# Check if a custom config path is provided
config_path = DEFAULT_CONFIG_PATH
if len(sys.argv) > 2 and sys.argv[2].endswith('.ini'):
    config_path = sys.argv[2]

# Load configuration from the ini file
config = configparser.ConfigParser()
config.read(config_path)

# API settings
imperva_url = config['Imperva_API']['url']
imperva_timeout = config['Imperva_API'].getint('timeout')

cloudflare_url = config['Cloudflare_API']['url']
cloudflare_timeout = config['Cloudflare_API'].getint('timeout')

# Email settings
ENABLE_SMTP = config['Email'].getboolean('enable_smtp')
SMTP_SERVER = config['Email']['smtp_server']
SMTP_PORT = int(config['Email']['smtp_port'])
SMTP_USERNAME = config['Email']['smtp_username']
SMTP_PASSWORD = config['Email']['smtp_password']
SMTP_TIMEOUT = config['Email'].getint('smtp_timeout')
EMAIL_FROM = config['Email']['email_from']
EMAIL_TO = config['Email']['email_to']
EMAIL_SUBJECT = config['Email']['email_subject']
EMAIL_TEMPLATE_FILE = os.path.join(script_dir, config['Email']['email_template'])

# Flock settings
ENABLE_FLOCK = config['Flock'].getboolean('enable_flock')
FLOCK_WEBHOOK_URL = config['Flock']['flock_webhook_url']
FLOCK_TIMEOUT = config['Flock'].getint('flock_timeout')

# File paths
IP_FILE = config['Files']['ip_file']
IPV6_FILE = config['Files']['ipv6_file']

# Apache settings
APACHE_RELOAD_COMMAND = config['Apache']['apache_reload_command'].split()

# F5 settings
F5_HOST = config['F5']['f5_host']
F5_USERNAME = config['F5']['f5_username']
F5_PASSWORD = config['F5']['f5_password']
F5_IP_LIST_NAME = config['F5']['f5_ip_list_name']
F5_SSL_VERIFY = config['F5']['f5_ssl_verify']
F5_TIMEOUT = config['F5'].getint('f5_timeout')

# Logging settings
LOG_FILE = config['Logging']['log_file']
DEBUG = config['Logging'].getboolean('debug')

# Set up logging configuration
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Disable SSL warnings if SSL verification is disabled
if F5_SSL_VERIFY.lower() == 'false':
    F5_SSL_VERIFY = False
elif os.path.isfile(F5_SSL_VERIFY):
    F5_SSL_VERIFY = F5_SSL_VERIFY  # Use the specified certificate file
else:
    logging.error("Invalid SSL verification setting. Exiting.")
    sys.exit(1)

if F5_SSL_VERIFY is False:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_help():
    help_message = """
    Usage: update_ips.py [PROVIDER] [OPTION] [CONFIG_PATH]

    PROVIDER:
      imperva  - Use Imperva as the IP provider.
      cloudflare - Use Cloudflare as the IP provider.

    Options:
      apache    - Update IP ranges in Apache and reload the service.
      f5        - Update IP ranges on F5 BIG-IP device.
      help      - Display this help message.

    CONFIG_PATH: Optional, specify a custom path to the config.ini file.
    """
    print(help_message)

# Function to send an email alert
def send_email(error_message):
    with open(EMAIL_TEMPLATE_FILE, 'r') as file:
        template = file.read()

    # Replace placeholder with actual error message
    body = template.replace('{{ error_message }}', error_message)

    msg = MIMEMultipart('alternative')
    msg['Subject'] = EMAIL_SUBJECT
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    msg.attach(MIMEText(body, 'html'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
            server.starttls()  # Upgrade the connection to a secure TLS/SSL
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, [EMAIL_TO], msg.as_string())
        logging.info("Email sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")

# Function to send an alert to Flock
def send_flock_alert(error_message):
    payload = {
        "flockml": f"<flockml><b>{EMAIL_SUBJECT}</b></br>{error_message}</flockml>"
    }

    try:
        response = requests.post(FLOCK_WEBHOOK_URL, json=payload, timeout=FLOCK_TIMEOUT)
        if response.status_code == 200:
            logging.info("Flock alert sent successfully.")
        else:
            logging.error(f"Failed to send Flock alert: HTTP {response.status_code} - {response.text}")
    except Exception as e:
        logging.error(f"Error sending Flock alert: {e}")

# Function to test SMTP connection
def test_smtp_connection():
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
        logging.info("SMTP connection test succeeded.")
        return True
    except Exception as e:
        logging.error(f"SMTP connection test failed: {e}")
        return False

# Function to load data from a file
def load_data_from_file(filename):
    try:
        with open(filename, 'r') as file:
            return file.read().splitlines()
    except FileNotFoundError:
        logging.warning(f"File {filename} not found. Treating as empty.")
        return []

# Function to save data to a file
def save_data_to_file(filename, data):
    with open(filename, 'w') as file:
        file.write("\n".join(data) + "\n")
    logging.info(f"Data saved to {filename}.")

# Function to reload Apache2 service
def reload_apache2():
    try:
        subprocess.run(APACHE_RELOAD_COMMAND, check=True)
        logging.info("Apache2 reloaded successfully.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to reload Apache2: {e}")

# Function to fetch current IP list from F5 BIG-IP
def fetch_f5_ip_list():
    logging.info("Fetching current IP list from F5 BIG-IP.")
    url = f"https://{F5_HOST}/mgmt/tm/ltm/data-group/internal/{F5_IP_LIST_NAME}"

    headers = {'Content-Type': 'application/json'}
    auth = HTTPBasicAuth(F5_USERNAME, F5_PASSWORD)

    try:
        response = requests.get(url, headers=headers, auth=auth, verify=F5_SSL_VERIFY, timeout=F5_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            current_ips = [record['name'] for record in data.get('records', [])]
            logging.debug(f"Current F5 IP list: {current_ips}")
            return current_ips
        else:
            error_message = f"Failed to fetch F5 IP list: HTTP {response.status_code} - {response.text}"
            logging.error(error_message)
            if ENABLE_SMTP:
                send_email(error_message)
            if ENABLE_FLOCK:
                send_flock_alert(error_message)
            sys.exit(1)  # Exit the script with an error status
    except Exception as e:
        error_message = f"Error fetching F5 IP list: {e}"
        logging.error(error_message)
        if ENABLE_SMTP:
            send_email(error_message)
        if ENABLE_FLOCK:
            send_flock_alert(error_message)
        sys.exit(1)  # Exit the script with an error status

# Function to update IP list on F5 BIG-IP
def update_f5_ip_list(ip_ranges):
    current_ip_ranges = fetch_f5_ip_list()

    # Compare the current list with new IP ranges
    if set(ip_ranges) != set(current_ip_ranges):
        logging.info("Updating F5 BIG-IP IP list.")
        url = f"https://{F5_HOST}/mgmt/tm/ltm/data-group/internal/{F5_IP_LIST_NAME}"

        headers = {'Content-Type': 'application/json'}
        auth = HTTPBasicAuth(F5_USERNAME, F5_PASSWORD)

        data = {
            "records": [{"name": ip} for ip in ip_ranges]
        }

        try:
            response = requests.put(url, json=data, headers=headers, auth=auth, verify=F5_SSL_VERIFY, timeout=F5_TIMEOUT)
            if response.status_code == 200:
                logging.info("F5 IP list updated successfully.")
            else:
                error_message = f"Failed to update F5 IP list: HTTP {response.status_code} - {response.text}"
                logging.error(error_message)
                if ENABLE_SMTP:
                    send_email(error_message)
                if ENABLE_FLOCK:
                    send_flock_alert(error_message)
                sys.exit(1)
        except Exception as e:
            error_message = f"Error updating F5 IP list: {e}"
            logging.error(error_message)
            if ENABLE_SMTP:
                send_email(error_message)
            if ENABLE_FLOCK:
                send_flock_alert(error_message)
            sys.exit(1)
    else:
        logging.info("No changes detected in the F5 IP list. No update needed.")

# Function to process IP ranges and update files, F5, and Apache
def imperva_process_ip_ranges(url, timeout, update_f5):
    # Check if SMTP is enabled and test the connection
    if ENABLE_SMTP:
        logging.debug("SMTP is enabled, testing the connection.")
        if not test_smtp_connection():
            logging.error("Exiting script due to failed SMTP connection.")
            sys.exit(1)
    else:
        logging.debug("SMTP is disabled.")

    try:
        response = requests.get(url=url, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        error_message = f"Request to {url} timed out after {timeout} seconds."
        logging.error(error_message)
        if ENABLE_SMTP:
            send_email(error_message)
        if ENABLE_FLOCK:
            send_flock_alert(error_message)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        error_message = f"Error during API request: {e}"
        logging.error(error_message)
        if ENABLE_SMTP:
            send_email(error_message)
        if ENABLE_FLOCK:
            send_flock_alert(error_message)
        sys.exit(1)

    # Check if the request was successful
    if response.status_code == 200:
        logging.debug("Received a successful response from API.")
        data = response.json()

        if data.get('res_message') == 'OK':
            logging.debug("API response indicates success.")

            # Only interact with files and Apache if update_f5 is False
            if not update_f5:
                # Load existing data from files
                old_ip_ranges = load_data_from_file(IP_FILE)
                old_ipv6_ranges = load_data_from_file(IPV6_FILE)

                # Get new data from the API response
                new_ip_ranges = data.get('ipRanges', [])
                new_ipv6_ranges = data.get('ipv6Ranges', [])

                # Log detailed debug information
                logging.debug(f"Old IP ranges: {old_ip_ranges}")
                logging.debug(f"New IP ranges: {new_ip_ranges}")
                logging.debug(f"Old IPv6 ranges: {old_ipv6_ranges}")
                logging.debug(f"New IPv6 ranges: {new_ipv6_ranges}")

                # Check if there's a difference in IP ranges
                if new_ip_ranges != old_ip_ranges or new_ipv6_ranges != old_ipv6_ranges:
                    logging.info("Changes detected in IP ranges. Updating files and reloading Apache2.")

                    # Save new data to files
                    save_data_to_file(IP_FILE, new_ip_ranges)
                    save_data_to_file(IPV6_FILE, new_ipv6_ranges)

                    # Reload Apache2 service
                    reload_apache2()
                else:
                    logging.info("No changes detected. No action needed.")
            else:
                # If in F5 mode, just update F5
                new_ip_ranges = data.get('ipRanges', [])
                update_f5_ip_list(new_ip_ranges)
        else:
            error_message = f"API returned a non-OK message: {data.get('res_message')}"
            logging.error(error_message)
            if ENABLE_SMTP:
                send_email(error_message)
            if ENABLE_FLOCK:
                send_flock_alert(error_message)
    else:
        error_message = f"Failed to retrieve data: HTTP {response.status_code}"
        logging.error(error_message)
        if ENABLE_SMTP:
            send_email(error_message)
        if ENABLE_FLOCK:
            send_flock_alert(error_message)

def cloudflare_process_ip_ranges(url, timeout, update_f5):
    logging.debug("Start cloudflare_process_ip_ranges()")
    if ENABLE_SMTP:
        logging.debug("SMTP is enabled, testing the connection.")
        if not test_smtp_connection():
            logging.error("Exiting script due to failed SMTP connection.")
            sys.exit(1)
    else:
        logging.debug("SMTP is disabled.")

    try:
        response = requests.get(url=url, headers={'Content-Type': 'application/json'}, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        error_message = f"Request to {url} timed out after {timeout} seconds."
        logging.error(error_message)
        if ENABLE_SMTP:
            send_email(error_message)
        if ENABLE_FLOCK:
            send_flock_alert(error_message)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        error_message = f"Error during API request: {e}"
        logging.error(error_message)
        if ENABLE_SMTP:
            send_email(error_message)
        if ENABLE_FLOCK:
            send_flock_alert(error_message)
        sys.exit(1)

    if response.status_code == 200:
        logging.debug("Received a successful response from API.")
        data = response.json()

        if data.get('success', False):
            logging.debug("API response indicates success.")

            ipv4_ranges = data['result'].get('ipv4_cidrs', [])
            ipv6_ranges = data['result'].get('ipv6_cidrs', [])

            if not update_f5:
                # Load existing data from files
                old_ipv4_ranges = load_data_from_file(IP_FILE)
                old_ipv6_ranges = load_data_from_file(IPV6_FILE)

                logging.debug(f"Old IPv4 ranges: {old_ipv4_ranges}")
                logging.debug(f"New IPv4 ranges: {ipv4_ranges}")
                logging.debug(f"Old IPv6 ranges: {old_ipv6_ranges}")
                logging.debug(f"New IPv6 ranges: {ipv6_ranges}")

                if ipv4_ranges != old_ipv4_ranges:
                    logging.info("Changes detected in IPv4 ranges. Updating files and reloading Apache2.")
                    save_data_to_file(IP_FILE, ipv4_ranges)
                    reload_apache2()

                if ipv6_ranges != old_ipv6_ranges:
                    logging.info("Changes detected in IPv6 ranges. Updating files and reloading Apache2.")
                    save_data_to_file(IPV6_FILE, ipv6_ranges)
                    reload_apache2()
            else:
                combined_ranges = ipv4_ranges + ipv6_ranges
                logging.info("Updating F5 with combined IPv4 and IPv6 ranges.")
                update_f5_ip_list(combined_ranges)
        else:
            error_message = f"API returned a non-success response: {data}"
            logging.error(error_message)
            if ENABLE_SMTP:
                send_email(error_message)
            if ENABLE_FLOCK:
                send_flock_alert(error_message)
    else:
        error_message = f"Failed to retrieve data: HTTP {response.status_code}"
        logging.error(error_message)
        if ENABLE_SMTP:
            send_email(error_message)
        if ENABLE_FLOCK:
            send_flock_alert(error_message)

# Main script execution based on arguments
if __name__ == "__main__":

    if len(sys.argv) < 3:
        print_help()
        sys.exit(1)

    provider = sys.argv[1].lower()
    option = sys.argv[2].lower()

    if provider not in ["imperva", "cloudflare"]:
        logging.error("Invalid provider specified.")
        print_help()
        sys.exit(1)

    if option not in ["apache", "f5"]:
        logging.error("Invalid option specified.")
        print_help()
        sys.exit(1)

    if provider == "imperva":
        logging.info("Selected provider: Imperva")
        if option == "apache":
            update_f5=False
            imperva_process_ip_ranges(imperva_url, imperva_timeout, update_f5)
        elif option == "f5":
            update_f5=True
            imperva_process_ip_ranges(imperva_url, imperva_timeout, update_f5)
    elif provider == "cloudflare":
        logging.info("Selected provider: Cloudflare")
        if option == "apache":
            update_f5=False
            cloudflare_process_ip_ranges(cloudflare_url, cloudflare_timeout, update_f5)
        elif option == "f5":
            update_f5=True
            cloudflare_process_ip_ranges(cloudflare_url, cloudflare_timeout, update_f5)
    else:
        print("Invalid option specified.")
        print_help()
