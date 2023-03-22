# SBOM Generator
This is a simple Python script to generate a CycloneDX Software Bill of Materials (SBOM) from a Checkmarx AST scan. The script requires an environment variable named SBOM_API_KEY to be set with the API key value from the Checkmarx AST UI.

## Dependencies
The script uses the following Python modules:

- os
- requests
- json
- xml.etree.ElementTree
- urllib3

## Usage
To use the script, run the following command:

```console
python sbom_generator.py
```

The script will prompt you to enter the Scan ID and the report format (json or xml). The SBOM report will be generated with the name SCAN_ID.json or SCAN_ID.xml depending on the format selected.

## Configuration
The following variables can be configured:

- API_URL_JSON: The URL to download the SBOM report in JSON format.
- API_URL_XML: The URL to download the SBOM report in XML format.
- iam_url: The URL of the Checkmarx IAM service.
- tenant: The name of the Checkmarx tenant.
- To configure these variables, update the values in the script.

## Disclaimer
This script is provided as-is and is not an official Checkmarx product. Use at your own risk.