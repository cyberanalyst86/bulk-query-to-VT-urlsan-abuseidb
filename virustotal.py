import requests
import json
import os
import re
import pandas as pd
import datetime

#-----------------------------VirusTotal_Metadata-------------------------------#

def query_ip_address_virustotal_metadata(ip_address):

#-----------------------------Definition-------------------------------#

    ip_query_result_url = "https://www.virustotal.com/gui/ip-address/"
    json_level_3 = ["regional_internet_registry" , "network", "tags","country","as_owner"]
    json_level_4 = ["harmless", "malicious", "suspicious" , "undetected"]

    query_url = "https://www.virustotal.com/api/v3/ip_addresses/" + str(ip_address)

    headers = {
        "accept": "application/json",
        "x-apikey": ""
    }

    num_detection_list = []
    attribute_list = []

#-----------------------------Get Response-------------------------------#
    try:

        response = requests.get(query_url, headers=headers)

    except FileNotFoundError:

        print('virustotal query error')

    json_object = json.loads(response.text)

    for attr in json_level_4:

        num_detection_list.append(json_object["data"]["attributes"]["last_analysis_stats"][attr])

    sum_of_detection = sum(num_detection_list)
    detection = json_object["data"]["attributes"]["last_analysis_stats"]["malicious"]

    detection = "detection : " + str(detection) + " of " + str(sum_of_detection)

    attribute_list.append(detection)

    for attr in json_level_3:

        try:

            attribute_list.append(str(attr) + " : " + str(json_object["data"]["attributes"][attr]))

        except KeyError:

            attribute_list.append("private ip")
            print('private ip')

# -----------------------------Format Attributes-------------------------------#

    # -----------------------------Convert Epoch Time-------------------------------#

    #last_analysis_date = attribute_list[5].split(":")

    #epoch_time = datetime.datetime.fromtimestamp(int(last_analysis_date[1]))

    #attribute_list[5] = "last_analysis_date : " + str(epoch_time)

    # -----------------------------Get Detection Breakdown------------------------------#

    last_analysis_stats = json_object["data"]["attributes"]["last_analysis_stats"]

    last_analysis_stats_lst_item = "detection breakdown : " + str(last_analysis_stats)

    attribute_list.append(last_analysis_stats_lst_item)

    # -----------------------------Get VT URL ------------------------------#

    vt_result_url = ip_query_result_url + str(ip_address)

    attribute_list.append("VT link : " + str(vt_result_url))

# -----------------------------Get Attribute List Json String------------------------------#

    jsonStr = json.dumps(attribute_list, indent=2)

    return jsonStr, attribute_list , vt_result_url

#-----------------------------VirusTotal_Metadata-------------------------------#

def query_domain_virustotal_metadata(domain):

    #-----------------------------Definition-------------------------------#

    domain_query_result_url = "https://www.virustotal.com/gui/domain/"
    json_level_4 = ["harmless", "malicious", "suspicious" , "undetected"]

    query_url = "https://www.virustotal.com/api/v3/domains/" + str(domain)

    headers = {
        "accept": "application/json",
        "x-apikey": ""
    }

    num_detection_list = []
    attribute_list = []

    #-----------------------------Get Response-------------------------------#
    try:

        response = requests.get(query_url, headers=headers)

    except FileNotFoundError:

        print('virustotal query error')

    json_object = json.loads(response.text)

    if response.status_code != 400:

        for attr in json_level_4:

            num_detection_list.append(json_object["data"]["attributes"]["last_analysis_stats"][attr])

        sum_of_detection = sum(num_detection_list)
        detection = json_object["data"]["attributes"]["last_analysis_stats"]["malicious"]

        detection = "detection : " + str(detection) + " of " + str(sum_of_detection)

        attribute_list.append(detection)

        # -----------------------------Get Detection Breakdown------------------------------#

        last_analysis_stats = json_object["data"]["attributes"]["last_analysis_stats"]

        last_analysis_stats_lst_item = "detection breakdown : " + str(last_analysis_stats)

        attribute_list.append(last_analysis_stats_lst_item)

        try:

            url = re.findall(r"Domain registrar url.*", json_object["data"]["attributes"]["whois"])[0].split(":")
            country = re.findall(r"Registrant country.*", json_object["data"]["attributes"]["whois"])[0].split(":")
            ns = re.findall(r"Name server.*", json_object["data"]["attributes"]["whois"])
            create_date = re.findall(r"Create date.*", json_object["data"]["attributes"]["whois"])[0].split(":")
            update_date = re.findall(r"Update date.*", json_object["data"]["attributes"]["whois"])[0].split(":")
            expiry_date = re.findall(r"Expiry date.*", json_object["data"]["attributes"]["whois"])[0].split(":")


            whois_dict ={

                url[0] : url[1],
                country[0] : country[1],
                "ns" : ns,
                create_date[0] : create_date[1],
                update_date[0] : update_date[1],
                expiry_date[0] : expiry_date[1]
            }

            for key, value in whois_dict.items():

                attribute_list.append(str(key) + " : " + str(value))

        except KeyError:

            whois_dict = {

                "url": "NIL",
                "country": "NIL",
                "ns": "NIL",
                "create date": "NIL",
                "update date": "NIL",
                "expiry_date": "NIL"
            }

        except IndexError:

            whois_dict = {

                "url": "NIL",
                "country": "NIL",
                "ns": "NIL",
                "create date": "NIL",
                "update date": "NIL",
                "expiry_date": "NIL"
            }


            for key, value in whois_dict.items():
                attribute_list.append(str(key) + " : " + str(value))


        # -----------------------------Get VT URL ------------------------------#

        vt_result_url = domain_query_result_url + str(domain)

        attribute_list.append("VT link : " + str(vt_result_url))

    # -----------------------------Get Attribute List Json String------------------------------#

        jsonStr = json.dumps(attribute_list, indent=2)

        return jsonStr, attribute_list , vt_result_url



    else:

        attribute_list.append("error 400")
        attribute_list.append("error 400")

        whois_dict = {

            "url": "error 400" ,
            "country" : "error 400",
            "ns": "error 400",
            "create_date": "error 400",
            "update_date": "error 400",
            "expiry_date": "error 400"
        }

        for key, value in whois_dict.items():
            attribute_list.append(str(key) + " : " + str(value))

        # -----------------------------Get VT URL ------------------------------#

        vt_result_url = domain_query_result_url + str(domain)

        attribute_list.append("VT link : " + str(vt_result_url))

        jsonStr = json.dumps(attribute_list, indent=2)

        return jsonStr, attribute_list, vt_result_url


def query_url_virustotal_metadata(query_artifact):

    url = "https://www.virustotal.com/api/v3/urls"
    url_result_url = "https://www.virustotal.com/gui/url/"
    json_level_2 = ["threat_names" , "reputation", "first_submission_date"]
    json_level_4 = ["harmless", "malicious", "suspicious", "undetected"]

    payload = "url=" + query_artifact
    headers = {
        "accept": "application/json",
        "x-apikey": "",
        "content-type": "application/x-www-form-urlencoded"
    }

    num_detection_list = []
    attribute_list = []

    response = requests.post(url, data=payload, headers=headers)

    json_object = json.loads(response.text)

    id = json_object["data"]["id"].split("-")[1]


    query_url = "https://www.virustotal.com/api/v3/urls/" + str(id)


    response = requests.get(query_url, headers=headers)

    json_object = json.loads(response.text)

    #print(json_object["data"]["attributes"]["threat_names"])
    #print(json_object["data"]["attributes"]["reputation"])
    #print(json_object["data"]["attributes"]["last_analysis_stats"])
    #print(json_object["data"]["attributes"]["first_submission_date"])

    for attr in json_level_4:
        num_detection_list.append(json_object["data"]["attributes"]["last_analysis_stats"][attr])

    sum_of_detection = sum(num_detection_list)
    detection = json_object["data"]["attributes"]["last_analysis_stats"]["malicious"]

    detection = "detection : " + str(detection) + " of " + str(sum_of_detection)

    attribute_list.append(detection)

    for attr in json_level_2:

        attribute_list.append(str(attr) + " : " + str(json_object["data"]["attributes"][attr]))

    # -----------------------------Format Attributes-------------------------------#

        # -----------------------------Convert Epoch Time-------------------------------#

    first_submission_date = attribute_list[3].split(":")

    epoch_time = datetime.datetime.fromtimestamp(int(first_submission_date[1]))

    attribute_list[3] = "first_submission_date: " + str(epoch_time)

    # -----------------------------Get Detection Breakdown------------------------------#

    last_analysis_stats = json_object["data"]["attributes"]["last_analysis_stats"]

    last_analysis_stats_lst_item = "detection breakdown : " + str(last_analysis_stats)

    attribute_list.append(last_analysis_stats_lst_item)

    # -----------------------------Get VT URL ------------------------------#

    vt_result_url = url_result_url + str(id)

    attribute_list.append("VT link : " + str(vt_result_url))

    # -----------------------------Get Attribute List Json String------------------------------#

    jsonStr = json.dumps(attribute_list, indent=2)

    return jsonStr, attribute_list , vt_result_url
