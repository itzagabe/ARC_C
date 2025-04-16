import nvdlib
import re
from datetime import datetime, timedelta, date
from private_key import key

import threading
from PySide6.QtWidgets import QApplication, QDialog, QVBoxLayout, QListWidget, QPushButton, QLabel
from PySide6.QtCore import Qt

officialCPE = []
notFoundDevices = []
refineSearchDevices = []
timeoutTimer = 5
delay = 3 #DELAY TIMER, 2 = lowest, may end up getting blocked from NVD if too many calls

def searchPLCInfoNVD(searchTermList, refinedSearch = True):
    global officialCPE, notFoundDevices, refineSearchDevices, timeoutTimer
    # Clear global lists
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
        threading.Thread(target=call_searchNVDCPE, args=(cpeTerm, cpeList, event)).start()

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
            selected_cpe = chooseWhichCPE(cpeList, cpeTerm, idx, listLength, count)
            if selected_cpe:
                officialCPE.append((selected_cpe, count))
            else:
                notFoundDevices.append(cpeTerm)

    if notFoundDevices or refineSearchDevices:
        showNotFoundDevicesPopup(notFoundDevices, refineSearchDevices)

    # Create the final list with CPEs and their corresponding CVEs
    cpe_cve_list = []
    for cpe, count in officialCPE:
        cve_list = searchNVD(cpe)
        refinedCVEList = getLatestCVEList(cve_list) # get refined CVE list
        cpe_cve_list.extend([(cpe, [(cve, True) for cve in refinedCVEList])] * count)

    return cpe_cve_list

def call_searchNVDCPE(cpeTerm, cpeList, event):
    try:
        result = searchNVDCPE(cpeTerm)
        if result:
            cpeList.extend(result)
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        event.set()

def chooseWhichCPE(cpeList, cpeTerm, idx, listLength, count):
    app = QApplication.instance() or QApplication([])

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
    #confirm_button.setStyleSheet("background-color: blue; border-radius: 3px; color: white;")
    layout.addWidget(confirm_button)

    def on_confirm():
        dialog.accept()

    confirm_button.clicked.connect(on_confirm)

    if dialog.exec():
        selected_item = list_widget.currentItem()
        return selected_item.text() if selected_item else None
    return None

def showNotFoundDevicesPopup(notFoundDevices, refineSearchDevices):
    app = QApplication.instance() or QApplication([])

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

def searchNVDCPE(model):
    print(f"searching {model}")
    try:
        if model.startswith("cpe:"):
            model = model[:-2]
            cveList = nvdlib.searchCPE(cpeMatchString=model, key= key, delay = delay)
        else:
            cveList = nvdlib.searchCPE(keywordSearch=model, key= key, delay = delay)
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    return cveList


def searchNVD(cpe):
    print(f'searching cves for {cpe}')
    formatCPE = str(cpe)
    # find a way to securely store the key somewhere
    cveList = nvdlib.searchCVE(cpeName = formatCPE, key= key, delay = delay)#, keywordExactMatch= True) #added exact match
    return cveList

def getDescriptionCVE(cveItem):
    return str(cveItem.descriptions[0].value)

def getCVE(cveItem):
    return str(cveItem.id)

def getBaseScoreCVE(cveItem):
    if cveItem.score[1] is not None:
        return cveItem.score[1]
    else:
        return -1

def getAvailabilityImpactCVE(cveItem):
    try:
        return cveItem.metrics.cvssMetricV31[0].availabilityImpact
    except AttributeError:
        try:
            return cveItem.metrics.cvssMetricV30[0].availabilityImpact
        except AttributeError:
            try:
               return cveItem.metrics.cvssMetricV2[0].availabilityImpact
            except AttributeError:
               return 0
        
def getConfidentialityImpactCVE(cveItem):
    try:
        return cveItem.metrics.cvssMetricV31[0].cvssData.confidentialityImpact
    except AttributeError:
        try:
            return cveItem.metrics.cvssMetricV30[0].confidentialityImpact
        except AttributeError:
            try:
               return cveItem.metrics.cvssMetricV2[0].confidentialityImpact
            except AttributeError:
               return 0
        
def getIntegrityImpactCVE(cveItem):
    try:
        return cveItem.metrics.cvssMetricV31[0].integrityImpact
    except AttributeError:
        try:
            return cveItem.metrics.cvssMetricV30[0].integrityImpact
        except AttributeError:
            try:
               return cveItem.metrics.cvssMetricV2[0].integrityImpact
            except AttributeError:
               return 0
        
def getImpactScoreCVE(cveItem):
    try:
        return cveItem.metrics.cvssMetricV31[0].impactScore
    except AttributeError:
        try:
            return cveItem.metrics.cvssMetricV30[0].impactScore
        except AttributeError:
            try:
               return cveItem.metrics.cvssMetricV2[0].impactScore
            except AttributeError:
               return 0

def getExploitabilityScoreCVE(cveItem):
    try:
        return cveItem.metrics.cvssMetricV31[0].exploitabilityScore
    except AttributeError:
        try:
            return cveItem.metrics.cvssMetricV30[0].exploitabilityScore
        except AttributeError:
            try:
               return cveItem.metrics.cvssMetricV2[0].exploitabilityScore
            except AttributeError:
               return 0
            
def getCVSS(cveItem):
    try:
        return cveItem.score, cveItem.v31vector
    except AttributeError:
        try:
            return cveItem.score, cveItem.v30vector 
        except AttributeError:
            try:
               return cveItem.score, cveItem.v2vector  
            except AttributeError:
               return 0

def getImpactConversion(cveWord):
    result = 0
    if cveWord == 'COMPLETE' or cveWord == 'HIGH':
        result = 10
    elif cveWord == 'PARTIAL' or cveWord == 'LOW':
        result = 6
    elif cveWord == 'NONE':
        result = 0
    return result

def getMultiplierCVE(cveItem):
    CVEYearString = cveItem.published
    cveYear = datetime(int(CVEYearString[0:4]), int(CVEYearString[5:7]), int(CVEYearString[8:10]))
    currentYear = datetime.today()
    yearDelta = (currentYear - cveYear).days // 365

    if yearDelta <= 0:
        return 1.0
    elif yearDelta <= 9:
        multiplier = 1.0 - (yearDelta * 0.1)
    else:
        multiplier = 0.1

    return multiplier

    # multiplier = 1
    # CVEYearString = cveItem.published
    # cveYear = datetime (int(CVEYearString[0:4]), int(CVEYearString[5:7]), int(CVEYearString[8:10]))
    # currentYear = datetime.today()
    # yearDelta = currentYear - cveYear
    # if int(yearDelta.days) <= 365:
    #     multiplier = 1
    # elif int(yearDelta.days) <= (2 * 365):
    #     multiplier = 0.9
    # elif int(yearDelta.days) <= (3 * 365):
    #     multiplier = 0.8
    # elif int(yearDelta.days) <= (4 * 365):
    #     multiplier = 0.7
    # elif int(yearDelta.days) <= (5 * 365):
    #     multiplier = 0.6
    # elif int(yearDelta.days) <= (6 * 365):
    #     multiplier = 0.5
    # elif int(yearDelta.days) <= (7 * 365):
    #     multiplier = 0.4
    # elif int(yearDelta.days) <= (8 * 365):
    #     multiplier = 0.3  
    # elif int(yearDelta.days) <= (9 * 365):
    #     multiplier = 0.2
    # else:
    #     multiplier = 0.1  

    # return multiplier

def getLatestCVEList(cveList):
    # Define the cutoff date
    cutoff_date = datetime.now() - timedelta(days=365 * 10)

    # Filter the list to include only CVEs that are not older than the cutoff date
    refined_cveList = [cve for cve in cveList if datetime.strptime(cve.published, '%Y-%m-%dT%H:%M:%S.%f') > cutoff_date]

    return refined_cveList
