import requests
import json
from selenium.webdriver.chrome.options import Options

#-----------------------------Abuseipdb_Metadata-------------------------------#

def query_abuseipdb_metadata(ip_address):

    abuseipdb_json_item = ["abuseConfidenceScore", "countryCode", "domain", "hostnames", "ipAddress", "isp", "lastReportedAt", "totalReports"]
    abuseipdb_json_item_excel = ["abuseConfidenceScore", "domain", "hostnames", "isp", "totalReports"]

#-----------------------------Defining the Api-Endpoint-----------------------------
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': ''
    }

    try:

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    except FileNotFoundError:

        print('abuseipdb query error')



#-----------------------------Formatted Output-----------------------------
    decodedResponse = json.loads(response.text)

# -----------------------------Get Filtered Abuseipdb Results-----------------------------

    abuseipdb_attr_list = []
    abuseipdb_attr_value_list = []

    for key, value in decodedResponse['data'].items():

        if key in abuseipdb_json_item:
            attribute_string = str(key) + " : " + str(value)

            abuseipdb_attr_value_list.append(value)
            abuseipdb_attr_list.append(attribute_string)

    # -----------------------------Get Abuseipdb URL ------------------------------#

    ip_query_result_url = "https://www.abuseipdb.com/check/"

    abuseipdb_result_url = ip_query_result_url + str(ip_address)

    abuseipdb_attr_list.append("abuseipdb link : " + str(abuseipdb_result_url))

# -----------------------------Get Attribute List Json String------------------------------#

    jsonStr = json.dumps(abuseipdb_attr_list, indent=2)

    return jsonStr , abuseipdb_attr_value_list, abuseipdb_result_url