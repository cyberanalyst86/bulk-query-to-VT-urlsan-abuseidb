import PySimpleGUI as sg
import os
import re
import pandas as pd

from virustotal import *
from abuseipdb import *
from abuseipdb_pdf import *
from virustotal_screenshot import *
from datetime import datetime
import time

def OSINT_Query_IP_Multiple(input_filepath):
    #--------------------------------Declare Variables---------------------------#

    df_excel_all = pd.DataFrame()
    df_excel_table = pd.DataFrame()

    abuseipdb_list = []
    virustotal_list = []
    vt_detection = []
    country = []
    vt_link = []
    abuseConfidenceScore = []
    isp = []
    domain = []
    hostnames = []
    total_reports = []
    abuseipdb_link = []

    #--------------------------------Date Time---------------------------#

    now = datetime.now()
    dt_string = now.strftime("%d-%m-%Y_%H-%M-%S")

    # ---------------read input csv as python dataframe ---------------#
    df_input = pd.read_excel(input_filepath)

    print(df_input)
    #----------------------------Check If IP or Domain/URL --------------------------------#

    ip_list = df_input.iloc[:,0].values.tolist()

    for i in range(len(ip_list)):

        match = re.match(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", ip_list[i])

        if match:

            print("Query IP address: " + str(ip_list[i]))
            # --------------------------------File Storage---------------------------#

            file_directory = "C:\\Users\\ongye\\Downloads\\osint_check_multiple"

            file_path = file_directory + "\\" + str(ip_list[i])

            isExist = os.path.exists(file_path)

            if isExist == False:

                os.mkdir(file_path)

            else:

                error = "error"


            # --------------------------------Get Abuseipdb Results---------------------------#

            abuseipdb_attributes, abuseipdb_attribute_value_list, abip_result_url = query_abuseipdb_metadata(ip_list[i])

            #screenshot_abuseipdb_pdf(ip_list[i], file_directory)
            # --------------------------------Get VT Results---------------------------#


            virustotal_attributes, vt_attribute_value_list, vt_result_url = query_ip_address_virustotal_metadata(
                ip_list[i])

            #screenshot_virustotal_ip(ip_list[i], file_directory)
            # --------------------------------AddtoDataFrame---------------------------#

            abuseipdb_list.append(abuseipdb_attributes)
            virustotal_list.append(virustotal_attributes)

            vt_detection.append(vt_attribute_value_list[0])
            country.append(vt_attribute_value_list[4])
            vt_link.append(vt_result_url)
            abuseConfidenceScore.append(abuseipdb_attribute_value_list[1])
            isp.append(abuseipdb_attribute_value_list[3])
            domain.append(abuseipdb_attribute_value_list[4])
            hostnames.append(abuseipdb_attribute_value_list[5])
            total_reports.append(abuseipdb_attribute_value_list[6])
            abuseipdb_link.append(abip_result_url)

            # --------------------------------OutputTextFile---------------------------#

            text_file_output_path = file_directory + "\\" + str(ip_list[i]) + "_result.txt"

            output_text = "VirusTotal:\n" + virustotal_attributes + "\n" + "Abuseipdb:\n" + abuseipdb_attributes

            f = open(text_file_output_path, "w")
            f.write(output_text)
            f.close()

        else:

            print("not IP address")

        time.sleep(5)

    #-------------------------DefineOutputFilePath---------------------------#

    dataframe_all_output_path=file_directory+"\\"+ str(dt_string) +"_result_consolidated.xlsx"
    dataframe_table_output_path=file_directory+"\\"+ str(dt_string) +"_result_table_consolidated.xlsx"


    #--------------------------------CreateDataFrame---------------------------#

    df_excel_all['IP']=ip_list
    df_excel_all['abuseipdb']=abuseipdb_list
    df_excel_all['virustotal']=virustotal_list


    df_excel_table['IP']=ip_list
    df_excel_table['virustotaldetection']=vt_detection
    df_excel_table['country']=country
    df_excel_table['virustotallink']=vt_link
    df_excel_table['abuseConfidenceScore']=abuseConfidenceScore
    df_excel_table['isp']=isp
    df_excel_table['domain']=domain
    df_excel_table['hostnames']=hostnames
    df_excel_table['total_reports']=total_reports
    df_excel_table['abuseipdblink']=abuseipdb_link


    #--------------------------------OutputDataFrame---------------------------#

    df_excel_all.to_excel(dataframe_all_output_path)
    df_excel_table.to_excel(dataframe_table_output_path)

    print("query completed !!!")

    return