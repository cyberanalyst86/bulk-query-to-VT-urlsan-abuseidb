import pandas as pd
import os
import requests
import sys
import time

filepath1= "C:\\Users\\Admin\\Downloads\\osint_check_multiple\\17-01-2023_10-06-26_result_table_consolidated_backdoor.xlsx"
filepath2= "C:\\Users\\Admin\\Downloads\\osint_check_multiple\\17-01-2023_11-50-25_result_table_consolidated_buffer_overflow.xlsx"
filepath3= "C:\\Users\\Admin\\Downloads\\osint_check_multiple\\17-01-2023_11-59-40_result_table_consolidated_vulnerability.xlsx"
filepath4= "C:\\Users\\Admin\\Downloads\\osint_check_multiple\\17-01-2023_15-15-31_result_table_consolidated_others.xlsx"

output_filepath = "C:\\Users\\Admin\\Downloads\\osint_check_multiple\\cci.xlsx"

#---------------read input csv as python dataframe ---------------#
df_combined = pd.DataFrame()
df1 = pd.read_excel(filepath1)
df2 = pd.read_excel(filepath2)
df3 = pd.read_excel(filepath3)
df4 = pd.read_excel(filepath4)

print(len(df1.index))
print(len(df2.index))
print(len(df3.index))
print(len(df4.index))

sum_df_len = len(df1.index) + len(df2.index) + len(df3.index) + len(df4.index)

print(sum_df_len)

df_combined = pd.concat([df1, df2, df3, df4])

print(len(df_combined.index))

#df_combined.to_excel(output_filepath)
