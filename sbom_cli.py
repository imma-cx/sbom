import argparse
import os
import requests
import json
import xml.etree.ElementTree as ET
import urllib3


# WIP WIP WIP WIP WIP

urllib3.disable_warnings()

parser = argparse.ArgumentParser(description='Generate CycloneDX reports from Checkmarx scans')
subparsers = parser.add_subparsers(dest='command', required=True)

# Configure command
configure_parser = subparsers.add_parser('configure', help='Configure the API URLs and IAM settings')
configure_parser.add_argument('--api-url-json', help='API URL for JSON format', required=True)
configure_parser.add_argument('--api-url-xml', help='API URL for XML format', required=True)
configure_parser.add_argument('--iam-url', help='IAM URL', required=True)
configure_parser.add_argument('--tenant', help='IAM tenant', required=True)

# Generate command
generate_parser = subparsers.add_parser('generate', help='Generate a CycloneDX report for a given scan ID')
generate_parser.add_argument('id', help='Scan ID')
generate_parser.add_argument('format', help='Report format (json or xml)')

args = parser.parse_args()

if args.command == 'configure':
    os.environ['API_URL_JSON'] = args.api_url_json
    os.environ['API_URL_XML'] = args.api_url_xml
    os.environ['IAM_URL'] = args.iam_url
    os.environ['IAM_TENANT'] = args.tenant
    print('Configuration updated successfully!')
    exit()

API_KEY = os.environ.get('SBOM_API_KEY')
API_URL_JSON = os.environ.get('API_URL_JSON')
API_URL_XML = os.environ.get('API_URL_XML')
IAM_URL = os.environ.get('IAM_URL')
IAM_TENANT = os.environ.get('IAM_TENANT')

if not all([API_KEY, API_URL_JSON, API_URL_XML, IAM_URL, IAM_TENANT]):
    raise Exception('Missing one or more required environment variables')

IAM_TOKEN_URL = f'{IAM_URL}/auth/realms/{IAM_TENANT}/protocol/openid-connect/token'

def get_access_token():
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    req_data = {
        "grant_type": "refresh_token",
        "client_id": "ast-app",
        "refresh_token": API_KEY,
    }

    response = requests.post(url=IAM_TOKEN_URL, json=req_data, headers=headers, verify=False)

    if response.status_code == 200:
        return response.json()['access_token']
    else:
        raise Exception('Failed to get access token: ' + response.text)

def get_report(id, format):
    access_token = get_access_token()

    if format == 'json':
        api_url = API_URL_JSON
    elif format == 'xml':
        api_url = API_URL_XML
    else:
        raise Exception('Invalid format: ' + format)

    headers = {'Authorization': 'Bearer ' + access_token}

    response = requests.get(api_url.format(id), headers=headers, verify=False)

    if response.status_code == 200:
        if format == 'json':
            return response.json()
        elif format == 'xml':
            return ET.fromstring(response.content)
    else:
        raise Exception('Failed to get report: ' + response.text)

if args.command == 'generate':
    id = args.id
    format = args.format

    report = get_report(id, format)

    if format == 'json':
        with open(id + '.json', 'w') as f:
            f.write(json.dumps(report))
        print('Report with name ' + id + '.json generated successfully!')
    elif format == 'xml':
        with open(id + '.xml', 'w') as f:
            f.write(json.dumps(report))
        print('Report with name ' + id + '.xml generated successfully!')
