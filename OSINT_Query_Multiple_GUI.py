import PySimpleGUI as sg
import os
import re
import pandas as pd
from OSINT_Query_IP_Multiple import *
from OSINT_Query_Domain_Multiple import *
from OSINT_Query_Url_Multiple import *
import time

# --------------------------------GUI---------------------------#
sg.theme('DarkAmber')  # Add a touch of color
# All the stuff inside your window.

layout = [
[sg.Text('Select query type',size=(30, 1),justification='left')],
    [sg.Combo(['IP Address', 'Domain', 'Url'],
                     key='type')],
    [sg.T("")], [sg.Text("Choose input file: "), sg.Input(), sg.FileBrowse(key="-IN-")],

          [sg.Button('Query')],
          ]

###Building Window
window = sg.Window('OSINT Query', layout, size=(600, 150))

while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == "Cancel":
        break
    elif event == "Query":
        dialog_input = values
        type = values['type']

        input_filepath = dialog_input['-IN-']

        head_tail = os.path.split(input_filepath)

        if type == "IP Address":

            OSINT_Query_IP_Multiple(input_filepath)

            break

        elif type == "Domain":

            OSINT_Query_Domain_Multiple(input_filepath)

            break


        elif type == "Url":

            OSINT_Query_Url_Multiple(input_filepath)

            break

        else:

            window['-OUTPUT-'].update('Error: input type not correct')

window.close()




