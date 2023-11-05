import requests
import json
import os
import re
import pandas as pd
import time
from bs4 import BeautifulSoup
from urlscan_img import *

def urlscan_domain (query_artifact):
#--------------------------Query urlscan for UUID--------------------------#
    urlscan_attr_list = []
    urlscan_attr_value_list = []

    headers = {'API-Key':'','Content-Type':'application/json'}

    data = {"url": query_artifact, "visibility": "public"}

    print(query_artifact)

    try:

        response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))

        print(response)

    except FileNotFoundError:

        print('urlscan query error')




        urlscan_result_url = response.json()["result"]

        query_url = "https://urlscan.io/api/v1/result/" + str(response.json()["uuid"])

        time.sleep(10)

#--------------------------Query urlscan for data--------------------------#

        try:

            response = requests.get(query_url, headers)

        except FileNotFoundError:

            print('urlscan query error')

        if response.status_code != 400:

            for key, value in response.json()['page'].items():

                attribute_string = str(key) + " : " + str(value)
                urlscan_attr_value_list.append(value)
                urlscan_attr_list.append(attribute_string)

            for key, value in response.json()['verdicts']['overall'].items():

                attribute_string = str(key) + " : " + str(value)
                urlscan_attr_value_list.append(value)
                urlscan_attr_list.append(attribute_string)

            urlscan_attr_list.append("urlscan link : " + str(urlscan_result_url))

            urlscan_img_url = urlscan_domain_img(query_artifact)

            urlscan_attr_list.append("urlscan screenshot link : " + str(urlscan_img_url ))

            jsonStr = json.dumps(urlscan_attr_list, indent=2)



            return jsonStr, urlscan_attr_value_list, urlscan_result_url, urlscan_img_url

        else:

            print("We could not scan this website!")
            print("This can happen for multiple reasons:")
            print(" - The site could not be contacted (DNS or generic network issues\n - The site uses insecure TLS (weak ciphers e.g.\n - The site requires HTTP authentication query_artifact")
            print("Take a look at the JSON output or the screenshot to determine a possible cause.")

            urlscan_result_url = "error 400"

            for i in range(16):
                urlscan_attr_value_list.append("error 400")
                urlscan_attr_list.append("error 400")

            urlscan_attr_list.append("urlscan link : " + str(urlscan_result_url))

            urlscan_img_url = "error 400"

            urlscan_attr_list.append("urlscan screenshot link : " + str(urlscan_img_url))

            jsonStr = json.dumps(urlscan_attr_list, indent=2)

            return jsonStr, urlscan_attr_value_list, urlscan_result_url, urlscan_img_url

    else:

        print("DNS Error - Could not resolve domain")
        print("Explanation")
        print("The domain " + str(query_artifact) + " could not be resolved to a valid IPv4/IPv6 address. We won't try to load it in the browser.")

        urlscan_result_url = "error 400"

        for i in range(16):

            urlscan_attr_value_list.append("error 400")
            urlscan_attr_list.append("error 400")

        urlscan_attr_list.append("urlscan link : " + str(urlscan_result_url))

        urlscan_img_url = "error 400"

        urlscan_attr_list.append("urlscan screenshot link : " + str(urlscan_img_url))

        jsonStr = json.dumps(urlscan_attr_list, indent=2)

        return jsonStr, urlscan_attr_value_list, urlscan_result_url, urlscan_img_url

def urlscan_url (query_artifact):

#--------------------------Query urlscan for UUID--------------------------#
    urlscan_attr_list = []
    urlscan_attr_value_list = []

    headers = {'API-Key':'','Content-Type':'application/json'}

    data = {"url": query_artifact, "visibility": "public"}

    try:

        response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))

    except FileNotFoundError:

        print('urlscan query error')

    if response.status_code != 400:

        urlscan_result_url = response.json()["result"]

        query_url = response.json()["api"]

        time.sleep(20)

#--------------------------Query urlscan for data--------------------------#

        try:

            response = requests.get(query_url, headers)

        except FileNotFoundError:

            print('urlscan query error')

        for key, value in response.json()['page'].items():

            attribute_string = str(key) + " : " + str(value)
            urlscan_attr_value_list.append(value)
            urlscan_attr_list.append(attribute_string)

        for key, value in response.json()['verdicts']['overall'].items():

            attribute_string = str(key) + " : " + str(value)
            urlscan_attr_value_list.append(value)
            urlscan_attr_list.append(attribute_string)

        urlscan_attr_list.append("urlscan link : " + str(urlscan_result_url))

        urlscan_img_url = urlscan_url_img(query_artifact)

        urlscan_attr_list.append("urlscan screenshot link : " + str(urlscan_img_url ))

        jsonStr = json.dumps(urlscan_attr_list, indent=2)

        return jsonStr, urlscan_attr_value_list, urlscan_result_url , urlscan_img_url

    else:

        domain = re.search(r"([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)", query_artifact)

        print("DNS Error - Could not resolve domain")
        print("Explanation")
        print("The domain " + str(
        domain.group(0)) + "could not be resolved to a valid IPv4/IPv6 address. We won't try to load it in the browser.")

