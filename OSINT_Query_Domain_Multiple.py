import PySimpleGUI as sg
import os
import re
import pandas as pd

from virustotal import *
from urlscan import *
from urlscan_screenshot import *
from virustotal_screenshot import *
from datetime import datetime
import time

def OSINT_Query_Domain_Multiple(input_filepath):
    #--------------------------------Declare Variables---------------------------#

    df_excel_all = pd.DataFrame()
    df_excel_table = pd.DataFrame()

    urlscan_list = []
    virustotal_list = []

    vt_detection = []
    domain_registrar_url = []
    registrant_country = []
    name_server = []
    create_date = []
    update_date = []
    expiry_date = []
    vt_link = []

    associated_ip = []
    asn = []
    asname = []
    urlscan_score = []
    urlscan_categories = []
    urlscan_malicious = []
    urlscan_link = []
    urlscan_screenshot_link = []


    #--------------------------------Date Time---------------------------#

    now = datetime.now()
    dt_string = now.strftime("%d-%m-%Y_%H-%M-%S")


    # ---------------read input csv as python dataframe ---------------#
    df_input = pd.read_excel(input_filepath)

    print(df_input)
    #----------------------------Check If IP or Domain/URL --------------------------------#

    domain_list = df_input.iloc[:,0].values.tolist()

    for i in range(len(domain_list)):

        match = re.match(r"([a-zA-Z0-9]+)(\.[a-zA-Z0-9.-]+)", domain_list[i])

        if match:

            print("Query Domain: " + str(domain_list[i]))
            # --------------------------------File Storage---------------------------#

            file_directory = "C:\\Users\\Admin\\Downloads\\osint_check_multiple"

            file_path = file_directory + "\\" + str(domain_list[i])

            isExist = os.path.exists(file_path)

            if isExist == False:

                os.mkdir(file_path)

            else:

                error = "error"


            # --------------------------------Get urlscan Results---------------------------#

            try:

                urlscan_attributes, urlscan_attribute_value_list, urlscan_result_url, urlscan_img_url = urlscan_domain(
                    domain_list[i])


                if urlscan_result_url != "error 400":

                    screenshot_urlscan_domain(domain_list[i], urlscan_result_url, file_directory)

                else:

                    print("error 400 , no screenshot")

            except TypeError:

                print("TypeError")

            # --------------------------------Get VT Results---------------------------#

            virustotal_attributes, vt_attribute_value_list, vt_result_url = query_domain_virustotal_metadata(
                domain_list[i])

            screenshot_virustotal_domain(domain_list[i], vt_result_url, file_directory)

            # --------------------------------AddtoDataFrame---------------------------#

            urlscan_list.append(urlscan_attributes)
            virustotal_list.append(virustotal_attributes)

            vt_detection.append(vt_attribute_value_list[0])
            domain_registrar_url.append(vt_attribute_value_list[2])
            registrant_country.append(vt_attribute_value_list[3])
            name_server.append(vt_attribute_value_list[4])
            create_date.append(vt_attribute_value_list[5])
            update_date.append(vt_attribute_value_list[6])
            expiry_date.append(vt_attribute_value_list[7])
            vt_link.append([vt_result_url])

            associated_ip.append(urlscan_attribute_value_list[5])
            asn.append(urlscan_attribute_value_list[6])
            asname.append(urlscan_attribute_value_list[7])

            try:

                urlscan_score.append(urlscan_attribute_value_list[8])
                urlscan_categories.append(urlscan_attribute_value_list[9])
                urlscan_malicious.append(urlscan_attribute_value_list[10])
                urlscan_link.append(urlscan_result_url)
                urlscan_screenshot_link.append(urlscan_img_url)

            except IndexError:


                urlscan_score.append(urlscan_attribute_value_list[2])
                urlscan_categories.append(urlscan_attribute_value_list[3])
                urlscan_malicious.append(urlscan_attribute_value_list[6])
                urlscan_link.append(urlscan_result_url)
                urlscan_screenshot_link.append(urlscan_img_url)


            # --------------------------------OutputTextFile---------------------------#

            text_file_output_path = file_directory + "\\" + str(domain_list[i]) + "_result.txt"

            output_text = "VirusTotal:\n" + virustotal_attributes + "\n" + "urlscan:\n" + urlscan_attributes

            f = open(text_file_output_path, "w")
            f.write(output_text)
            f.close()

        else:

            print("not domain")

        time.sleep(5)

    #-------------------------DefineOutputFilePath---------------------------#

    dataframe_all_output_path=file_directory+"\\" + str(dt_string) + "_result_consolidated.xlsx"
    dataframe_table_output_path=file_directory+"\\"+ str(dt_string) + "_result_table_consolidated.xlsx"


    #--------------------------------CreateDataFrame---------------------------#

    df_excel_all['domain']=domain_list
    df_excel_all['urlscan']=urlscan_list
    df_excel_all['virustotal']=virustotal_list

    df_excel_table['domain'] = domain_list
    df_excel_table['vt detection']=vt_detection
    df_excel_table['Domain registrar url']=domain_registrar_url
    df_excel_table['Registrant country']=registrant_country
    df_excel_table['Create Date']=create_date
    df_excel_table['Update Date']=update_date
    df_excel_table['Expirty Date']=expiry_date
    df_excel_table['VirusTotal link']=vt_link


    df_excel_table['associated ip']=associated_ip
    df_excel_table['asn']=asn
    df_excel_table['asname']=asname
    df_excel_table['urlscan score'] = urlscan_score
    df_excel_table['urlscan categories'] = urlscan_categories
    df_excel_table['urlscan malicious'] = urlscan_malicious
    df_excel_table['urlscan link'] = urlscan_link
    df_excel_table[ 'urlscan screenshot link'] = urlscan_screenshot_link




    #--------------------------------OutputDataFrame---------------------------#

    df_excel_all.to_excel(dataframe_all_output_path)
    df_excel_table.to_excel(dataframe_table_output_path)

    print("query completed !!!")

    return