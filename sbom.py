import os
import requests
import json
import xml.etree.ElementTree as ET
import urllib3
urllib3.disable_warnings()

# please, create the env variable with the API KEY using:
# export SBOM_API_KEY="KEY VALUE FROM CXONE UI"

API_KEY = os.environ.get('SBOM_API_KEY')
API_URL_JSON = 'https://deu.ast.checkmarx.net/api/sca/risk-management/risk-reports/{}/export?format=CycloneDxJson&dataType[]=all'
API_URL_XML = 'https://deu.ast.checkmarx.net/api/sca/risk-management/risk-reports/{}/export?format=CycloneDxXml&dataType[]=all'

iam_url = "https://deu.iam.checkmarx.net"
tenant = "emanuel_ribeiro_gst"

url = iam_url + "/auth/realms/" + tenant + "/protocol/openid-connect/token"
req_data = {
                "grant_type": "refresh_token",
                "client_id": "ast-app",
                "refresh_token": API_KEY,
            }

def get_access_token():
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    data = {'api_key': API_KEY}

    response = requests.post(url=url, data=req_data, verify=False)
    

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

if __name__ == '__main__':
    id = input('Enter the Scan ID: ')
    format = input('Enter the report format (json/xml): ')

    report = get_report(id, format)

    if format == 'json':
        with open(id + '.json', 'w') as f:
            f.write(json.dumps(report))
        print('Report with name ' + id + '.json generated successfully!')
    elif format == 'xml':
        with open(id + '.xml', 'wb') as f:
            f.write(ET.tostring(report))
        print('Report with name ' + id + '.xml generated successfully!')

    else:
        raise Exception('Invalid format: ' + format)