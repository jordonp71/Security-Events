import subprocess
import json
import os
import logging
import requests

def setup_logging():
    # Set up logging to both console and file
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(filename='container_security_scanner.log', level=logging.INFO, format=log_format)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter(log_format))
    logging.getLogger().addHandler(console_handler)

def scan_container_image(image_name, splunk_hec_url):
    try:
        # Run Trivy scan command and capture JSON output
        trivy_command = f'trivy --format json {image_name}'
        trivy_output = subprocess.check_output(trivy_command, shell=True)
        scan_results = json.loads(trivy_output)

        # Process scan results
        vulnerabilities = scan_results.get('Vulnerabilities', [])

        if vulnerabilities:
            logging.warning(f"Security vulnerabilities found in {image_name}:")
            for vuln in vulnerabilities:
                logging.warning(f" - {vuln['Title']} (Severity: {vuln['Severity']})")

            # Integrate with Splunk via HTTP Event Collector
            integrate_with_splunk(image_name, vulnerabilities, splunk_hec_url)
        else:
            logging.info(f"No security vulnerabilities found in {image_name}")

        # Generate a detailed report (CSV format in this example)
        generate_report(image_name, vulnerabilities)

    except subprocess.CalledProcessError as e:
        logging.error(f"Error scanning {image_name}: {e}")
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding Trivy output for {image_name}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

def generate_report(image_name, vulnerabilities):
    # Generate a detailed report in CSV format
    report_path = f"{image_name}_security_report.csv"
    with open(report_path, 'w') as report_file:
        report_file.write("Vulnerability,Severity,Description\n")
        for vuln in vulnerabilities:
            report_file.write(f"{vuln['Title']},{vuln['Severity']},{vuln['Description']}\n")
    logging.info(f"Detailed security report generated: {report_path}")

def integrate_with_splunk(image_name, vulnerabilities, splunk_hec_url):
    # Splunk HTTP Event Collector settings
    splunk_hec_token = 'your_splunk_hec_token'  # Replace with your Splunk HEC token
    splunk_hec_index = 'your_splunk_index'  # Replace with your Splunk index

    # Prepare event data for Splunk
    event_data = {
        'index': splunk_hec_index,
        'sourcetype': 'container_security_scanner',
        'event': {
            'image_name': image_name,
            'vulnerabilities': vulnerabilities
        }
    }

    # Send event data to Splunk via HEC
    headers = {'Authorization': f'Splunk {splunk_hec_token}'}
    response = requests.post(splunk_hec_url, json=event_data, headers=headers)

    if response.status_code == 200:
        logging.info(f"Security events sent to Splunk for {image_name}")
    else:
        logging.error(f"Failed to send security events to Splunk. Status Code: {response.status_code}, Response: {response.text}")

if __name__ == "__main__":
    setup_logging()

    # Replace 'your_container_image_name' and 'your_splunk_hec_url' with the actual values
    container_image_name = 'your_container_image_name'
    splunk_hec_url = 'your_splunk_hec_url'

    try:
        # Check if Trivy is installed
        subprocess.check_output(['trivy', '--version'])
    except subprocess.CalledProcessError:
        logging.error("Trivy is not installed. Please install Trivy before running the scanner.")
        exit(1)

    # Perform container image scan and integrate with Splunk
    scan_container_image(container_image_name, splunk_hec_url)
