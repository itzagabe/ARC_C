"""
Module for querying and processing vulnerability data from the NVD (National Vulnerability Database).
Includes functionality to search for CPEs, fetch related CVEs, and extract key metrics.
"""
import nvdlib
import threading
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from PySide6.QtWidgets import QDialog, QVBoxLayout, QListWidget, QPushButton, QLabel

# === Environment Setup ===
"""
Load the private key. You can request an NVD API key by visiting the official NIST website: https://nvd.nist.gov/developers/request-an-api-key
"""
load_dotenv()

private_key = os.getenv("PRIVATE_KEY")

if not private_key:
    print("PRIVATE_KEY not configured. For a more efficient query, please set it in the environment or a .env file.")

# === Global Config / State ===
officialCPE = []
notFoundDevices = []
refineSearchDevices = []
timeoutTimer = 5
delay = 3 # DELAY TIMER, 2 = lowest, may end up getting blocked from NVD if too many calls

def search_plc_info_nvd(searchTermList, refinedSearch = True):
    """
    Searches NVD for vulnerabilities related to a list of devices.
    - Inputs: 
     - searchTermList: A list of tuples where each tuple contains a CPE term and count.
     - refinedSearch: A boolean indicating whether the search should include refinement of the search terms (default is True).
    - Outputs:
     - A list of tuples containing the CPE name and its associated CVE information.
    Used by import_devices_ui.
    """
    global officialCPE, notFoundDevices, refineSearchDevices, timeoutTimer
    officialCPE = []
    notFoundDevices = []
    refineSearchDevices = []

    listLength = len(searchTermList)
    for idx, (cpeTerm, count) in enumerate(searchTermList):
        if len(cpeTerm) == 1:
            refineSearchDevices.append(cpeTerm)
            continue
        cpeList = []
        event = threading.Event()
        threading.Thread(target=call_search_nvd_cpe, args=(cpeTerm, cpeList, event)).start()

        if not event.wait(timeoutTimer):  #timeout
            refineSearchDevices.append(cpeTerm)
            continue
        
        if not refinedSearch:
            cpeList = [cpe for cpe in cpeList if "firmware" not in cpe.cpeName] # remove firmware from search

        if len(cpeList) == 0:
            notFoundDevices.append(cpeTerm)
        elif len(cpeList) == 1 or not refinedSearch:
            officialCPE.append((cpeList[0].cpeName, count))
        else:
            selected_cpe = choose_which_cpe(cpeList, cpeTerm, idx, listLength, count)
            if selected_cpe:
                officialCPE.append((selected_cpe, count))
            else:
                notFoundDevices.append(cpeTerm)

    if notFoundDevices or refineSearchDevices:
        showNotFoundDevicesPopup(notFoundDevices, refineSearchDevices)

    # Create the final list with CPEs and their corresponding CVEs
    cpe_cve_list = []
    for cpe, count in officialCPE:
        cve_list = search_nvd(cpe)
        refinedCVEList = get_latest_cve_list(cve_list) # get refined CVE list
        cpe_cve_list.extend([(cpe, [(cve, True) for cve in refinedCVEList])] * count)

    return cpe_cve_list

def call_search_nvd_cpe(cpeTerm, cpeList, event):
    """
    Responsible for querying NVD for CPE-related information asynchronously.
    Used by search_plc_info_nvd method.
    """
    try:
        result = search_nvd_cpe(cpeTerm)
        if result:
            cpeList.extend(result)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        event.set()

def choose_which_cpe(cpeList, cpeTerm, idx, listLength, count):
    """
    Prompts the operator to choose a CPE from a list of options using a GUI dialog.
    - Inputs:
      - cpeList: A list of CPE objects, each containing a cpeName to be presented to the user.
      - cpeTerm: The original CPE term used for the search.
    - Outputs:
      - A string representing the selected CPE name, or None if the user doesn't select any CPE.
    Used by search_plc_info_nvd method.
     """

    dialog = QDialog()
    dialog.setWindowTitle(f"Choose CPE for \"{cpeTerm}\" ({idx + 1} / {listLength}) - {count} devices")
    dialog.setMinimumWidth(1000)

    layout = QVBoxLayout()
    dialog.setLayout(layout)

    list_widget = QListWidget()
    cpeNames = [cpe.cpeName for cpe in cpeList]  # Extract cpeName from each element in cpeList
    list_widget.addItems(cpeNames)
    layout.addWidget(list_widget)

    confirm_button = QPushButton("Select")
    layout.addWidget(confirm_button)

    def on_confirm():
        dialog.accept()

    confirm_button.clicked.connect(on_confirm)

    if dialog.exec():
        selected_item = list_widget.currentItem()
        return selected_item.text() if selected_item else None
    return None

def showNotFoundDevicesPopup(notFoundDevices, refineSearchDevices):
    """
      Displays a popup dialog to inform the user about devices that were not found or need refinement in the search.
    - Inputs:
      - notFoundDevices: A list of device names that could not be found in the NVD.
      - refineSearchDevices: A list of device names that need further refinement to complete the search.
    - Outputs:
      - None (Displays a dialog with a list of devices and options to close the dialog).
     """
    
    dialog = QDialog()
    dialog.setWindowTitle("Devices Not Found or Need Refinement")
    dialog.setMinimumWidth(1500)  # Make the pop-out window wider

    layout = QVBoxLayout()
    dialog.setLayout(layout)

    if notFoundDevices:
        label_not_found = QLabel("The following devices could not be found:")
        layout.addWidget(label_not_found)
        list_widget_not_found = QListWidget()
        list_widget_not_found.addItems(notFoundDevices)
        layout.addWidget(list_widget_not_found)

    if refineSearchDevices:
        label_refine_search = QLabel("The following devices need search refinement:")
        layout.addWidget(label_refine_search)
        list_widget_refine_search = QListWidget()
        list_widget_refine_search.addItems(refineSearchDevices)
        layout.addWidget(list_widget_refine_search)

    close_button = QPushButton("Close")
    #close_button.setStyleSheet("background-color: blue; border-radius: 3px; color: white;")
    layout.addWidget(close_button)

    close_button.clicked.connect(dialog.accept)

    dialog.exec()

def search_nvd_cpe(model):
    print(f"searching {model}")
    try:
        if model.startswith("cpe:"):
            model = model[:-2]
            cveList = nvdlib.searchCPE(cpeMatchString=model, key=private_key if private_key != "None" else None, delay = delay)
        else:
            cveList = nvdlib.searchCPE(keywordSearch=model, key=private_key if private_key != "None" else None, delay = delay)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    return cveList


def search_nvd(cpe):
    print(f'searching cves for {cpe}')
    formatCPE = str(cpe)
    # find a way to securely store the key somewhere
    cveList = nvdlib.searchCVE(cpeName = formatCPE, key=private_key if private_key != "None" else None, delay = delay)#, keywordExactMatch= True) #added exact match
    return cveList

def get_confidentiality_impact_cve(cveItem):
    """
    Returns the confidentiality impact (None, Low, High) for a CVE item.
    """
    for attr in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        try:
            metrics = getattr(cveItem.metrics, attr)[0]
            return metrics.cvssData.confidentialityImpact if hasattr(metrics, "cvssData") else metrics.confidentialityImpact
        except (AttributeError, IndexError):
            continue
    return 0

def get_exploitability_score_cve(cveItem):
    """
    Returns the exploitability score [0, 3.9] for a CVE item.
    """
    for attr in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        try:
            metrics = getattr(cveItem.metrics, attr)[0]
            return metrics.exploitabilityScore
        except (AttributeError, IndexError):
            continue
    return 0

def get_latest_cve_list(cveList):
    """
    Filter the list to include only CVEs that are not older than the cutoff date.
    Cutoff date: 10 years from date program is run
    """
    cutoff_date = datetime.now() - timedelta(days=365 * 10)
    refined_cveList = [cve for cve in cveList if datetime.strptime(cve.published, '%Y-%m-%dT%H:%M:%S.%f') > cutoff_date]

    return refined_cveList
