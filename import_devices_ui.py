"""
Module for managing the device import UI panel in the application.
Provides functionality for importing devices individually, in groups, or manually, and for displaying vulnerability results. 
Handles calculation and display of the probability of software compromise based on active device CVEs.
"""
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QComboBox, QLineEdit, QPushButton, QDoubleSpinBox,
    QLabel, QCheckBox, QListWidget, QFileDialog, QStyle, QStackedLayout, QMessageBox, QDialog, QFrame, QListWidgetItem, QScrollArea
)
from PySide6.QtCore import Qt
from nvd import search_plc_info_nvd
from nvd import get_exploitability_score_cve, get_confidentiality_impact_cve
from shared_functions import create_result_button, update_result_button

# === Global Config / State ===
search_terms = []
detailed_search = False
deviceInfoList = []  # format [(cpe name, [(cve, status), (cve, status), etc]), (cpe name, [(cve, status), (cve, status), etc])]
results_to_device_map = {}

def show_error_popup(message):
    msg_box = QMessageBox()
    msg_box.setIcon(QMessageBox.Warning)
    msg_box.setText(message)
    msg_box.setWindowTitle("Error")
    msg_box.exec()

def handle_search(source, results_list, device_name_edit=None):
    """ 
    Performs a search based on the specified search term and updates the list of devices and CVEs.
    - Inputs:
      - source: Indicates if the search is individual or group-based.
      - device_name_edit: The input field for device name (only used for individual search).
    Updates the device list and populates the `deviceInfoList` and `results_to_device_map` globals for individual and group importing.
    """
    global search_terms, deviceInfoList, results_to_device_map

    if source == "Individual":
        device_name = device_name_edit.text().strip() if device_name_edit else ""
        if not device_name:
            show_error_popup("Please fill in the device name.")
            return
        search_terms.clear()
        search_terms.append((device_name, 1))

    try:
        # Perform search with the current search terms
        new_device_info_list = search_plc_info_nvd(search_terms, detailed_search)

        # Modify the structure to store CVE information with status
        updated_device_info_list = []
        for cpe, cves in new_device_info_list:
            updated_cves = []
            for cve, status in cves:
                confidentiality_impact = get_confidentiality_impact_cve(cve)
                if confidentiality_impact not in ['NONE', 'LOW', 'HIGH']:
                    confidentiality_impact = 'NONE'  # Default to NONE if the value is for some reason not valid

                cve_info = [cve.id, get_exploitability_score_cve(cve), confidentiality_impact]
                updated_cves.append((cve_info, status))
            updated_device_info_list.append((cpe, updated_cves))

        # Append new devices to the existing list
        deviceInfoList.extend(updated_device_info_list)

        # Clear and repopulate the results list
        results_list.clear()
        results_to_device_map.clear()
        for idx, (cpe, _) in enumerate(deviceInfoList):
            item = QListWidgetItem(cpe)
            results_list.addItem(item)
            results_to_device_map[idx] = item

        # Automatically calculate values after search
        get_import_values()

    except Exception as e:
        show_error_popup(f"An error occurred during search: {e}")



def handle_group_file_load(path_box):
    """ 
    Loads search terms from a file and updates the search term list (for group imports).
    Updates the global search_terms list with the contents of the loaded file.
    """
    file_dialog = QFileDialog()
    file_path, _ = file_dialog.getOpenFileName(None, "Open File", "", "All Files (*)")

    if file_path:
        path_box.setText(file_path)
        path_box.setStyleSheet("")  # Reset to default style if a file is loaded
        global search_terms
        search_terms = []
        search_term_counts = {}
        with open(file_path, 'r') as file:
            lines = file.readlines()
            for line in lines:
                if not line.startswith("#"):
                    search_term = line.strip()
                    if search_term in search_term_counts:
                        search_term_counts[search_term] += 1
                    else:
                        search_term_counts[search_term] = 1

        search_terms = [(term, count) for term, count in search_term_counts.items()]
    else:
        path_box.setPlaceholderText("File path will be displayed here")
        path_box.setStyleSheet("font-style: italic;")

def calculate_resilience(cves, b_d=0.03, c_w=2):
    """ 
    Calculates the "resilience" of a device based on its CVE exploitability and impact.
    - Inputs:
      - cves: List of CVE entries where each entry contains exploitability and impact details.
      - b_d: Base resilience value (default 0.03).
      - c_w: Weighting factor for exploitability (default 2).
    Returns the calculated resilience score of the device.
    """

    deviceResilience = 1
    for (cve_info, status) in cves:
        if status:  # Only consider active CVEs
            exploit = cve_info[1]
            impact = cve_info[2]

            if impact == 'NONE':
                quantizedExploit = 0.1 * (exploit / 3.9) ** c_w
            elif impact == 'LOW':
                quantizedExploit = 0.3 * (exploit / 3.9) ** c_w
            elif impact == 'HIGH':
                quantizedExploit = 1.0 * (exploit / 3.9) ** c_w

            deviceResilience *= 1 - quantizedExploit

    return b_d + (1 - b_d) * (1 - deviceResilience)


def show_cve_popup(item, results_list):
    """
    Displays a popup with the CVE details for a selected device.
    Used when double-clicking on a device in the imported devices list. 
    """
    global deviceInfoList, results_to_device_map
    idx = results_list.row(item)
    cpe, cves = deviceInfoList[idx]

    def toggleCVE(idx, cve_id, checked):
        for i in range(len(deviceInfoList[idx][1])):
            if deviceInfoList[idx][1][i][0][0] == cve_id:
                deviceInfoList[idx][1][i] = (deviceInfoList[idx][1][i][0], checked)
                break
        # Recalculate immediately after toggling CVE status
        get_import_values()
        update_device_compromise_button()

    def update_device_compromise_button():
        device_compromise = calculate_resilience(cves)
        update_result_button(device_compromise_button, device_compromise, "Probability of Compromise")

    def remove_device():
        reply = QMessageBox.question(
            None, 'Remove Device',
            f"Are you sure you want to remove the device {cpe}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            global deviceInfoList, results_to_device_map
            del deviceInfoList[idx]
            results_list.takeItem(idx)
            results_to_device_map.clear()
            for i in range(len(deviceInfoList)):
                results_to_device_map[i] = results_list.item(i)
            dialog.accept()
            # Recalculate after device removal
            get_import_values()

    dialog = QDialog()
    dialog.setWindowTitle(f"CVEs for {cpe}")

    main_layout = QVBoxLayout(dialog)

    scroll_area = QScrollArea()
    scroll_area.setWidgetResizable(True)
    scroll_area.setFrameShape(QScrollArea.NoFrame)  # Remove the bezel around the frame
    scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)  # Disable horizontal scroll
    scroll_content = QWidget()
    scroll_layout = QVBoxLayout(scroll_content)
    scroll_content.setLayout(scroll_layout)

    scroll_area.setWidget(scroll_content)
    main_layout.addWidget(scroll_area)

    device_compromise_button = create_result_button("#bababa")  # Initial color
    scroll_layout.addWidget(device_compromise_button, alignment=Qt.AlignCenter)
    update_device_compromise_button()

    for (cve_info, active) in cves:
        cve_id, exploitability_score, confidentiality_impact = cve_info
        checkbox = QCheckBox(f"{cve_id} (Exploitability: {exploitability_score}, Confidentiality: {confidentiality_impact})")
        checkbox.setChecked(active)
        checkbox.toggled.connect(lambda checked, cve_id=cve_id: toggleCVE(idx, cve_id, checked))
        scroll_layout.addWidget(checkbox)

    button_layout = QHBoxLayout()
    
    remove_button = QPushButton("Remove")
    remove_button.clicked.connect(lambda: [remove_device(), get_import_values()])
    button_layout.addWidget(remove_button)
    
    close_button = QPushButton("Close")
    close_button.clicked.connect(dialog.accept)
    close_button.setDefault(True)
    button_layout.addWidget(close_button)
    
    main_layout.addLayout(button_layout)

    dialog.exec()

# === Logic for the bottom half of the import device panel ===
def create_bottom_layout():

    bottom_layout = QHBoxLayout()
    imported_devices_label = QLabel("Imported Devices")
    imported_devices_label.setToolTip("This is the list of imported devices.")
    bottom_layout.addWidget(imported_devices_label, alignment=Qt.AlignLeft)

    detailed_search_layout = QHBoxLayout()
    detailed_search_label = QLabel("Detailed Search")
    detailed_search_label.setToolTip("Enable this for a more refined search.")
    detailed_search_checkbox = QCheckBox()
    detailed_search_checkbox.setToolTip("Enable this for a more refined search.")

    def toggle_detailed_search(state):
      global detailed_search
      detailed_search = bool(state)

    detailed_search_checkbox.stateChanged.connect(toggle_detailed_search)
    detailed_search_layout.addWidget(detailed_search_label)
    detailed_search_layout.addWidget(detailed_search_checkbox)

    bottom_layout.addLayout(detailed_search_layout)
    bottom_layout.setAlignment(detailed_search_layout, Qt.AlignRight)

    return bottom_layout

def create_results_list():
    results_list = QListWidget()
    results_list.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
    results_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    results_list.itemDoubleClicked.connect(lambda item: show_cve_popup(item, results_list))
    return results_list
# =========================================================

# === Logic for the top half of the import device panel ===
def create_individual_layout(results_list):
    """
    Logic for the individual device dropdown.
    """
    individual_layout = QVBoxLayout()
    device_name_edit = QLineEdit()
    device_name_edit.setPlaceholderText("Enter Device Name")
    device_name_edit.setStyleSheet("font-style: italic;")
    individual_layout.addWidget(device_name_edit)

    search_button = QPushButton("Search")
    search_button.clicked.connect(lambda: handle_search("Individual", results_list, device_name_edit))
    individual_layout.addWidget(search_button)

    return individual_layout

def create_group_layout(container, results_list):
    """
    Logic for the group device dropdown.
    """
    group_layout = QVBoxLayout()

    group_file_layout = QHBoxLayout()
    import_file_button = QPushButton()
    import_file_button.setIcon(container.style().standardIcon(QStyle.SP_DirOpenIcon))
    import_file_button.setFixedSize(20, 20)  # Adjusted size
    group_textbox = QLineEdit()
    group_textbox.setEnabled(False)
    group_textbox.setPlaceholderText("File path will be displayed here")
    group_textbox.setStyleSheet("font-style: italic;")
    import_file_button.clicked.connect(lambda: handle_group_file_load(group_textbox))
    group_file_layout.addWidget(import_file_button)

    group_file_layout.addWidget(group_textbox)
    group_layout.addLayout(group_file_layout)

    search_button = QPushButton("Search")
    search_button.clicked.connect(lambda: handle_search("Group", results_list))
    group_layout.addWidget(search_button)

    return group_layout

def create_manual_layout():
    """
    Logic for the manual device dropdown.
    """
    manual_layout = QVBoxLayout()

    add_device_button = QPushButton("Add Device")
    add_device_button.clicked.connect(handle_add_device)
    manual_layout.addWidget(add_device_button)
    search_button = QPushButton("Search")
    search_button.setEnabled(False)
    manual_layout.addWidget(search_button)


    return manual_layout

def handle_add_device(results_list):
    """ 
    Handles the addition of a new device using the manual import method, prompting the user for device and CVE details.
    Adds new devices and CVEs to `deviceInfoList` and updates the UI.
    """

    dialog = QDialog()
    dialog.setWindowTitle("Add Device")
    dialog.setFixedWidth(500)  # Set a fixed width for the dialog

    layout = QVBoxLayout()
    dialog.setLayout(layout)

    cpe_label = QLabel("Enter CPE Name:")
    cpe_name_edit = QLineEdit()
    cpe_name_edit.setPlaceholderText("Enter CPE Name")
    layout.addWidget(cpe_label)
    layout.addWidget(cpe_name_edit)

    cve_list_layout = QVBoxLayout()
    add_cve_button = QPushButton("Add CVE")
    cve_list_layout.addWidget(add_cve_button)

    cve_entries = []

    def add_cve_entry():
        form_layout = QHBoxLayout()
        cve_id_edit = QLineEdit()
        cve_id_edit.setPlaceholderText("Enter CVE ID")
        
        severity_spinbox = QDoubleSpinBox()  # Use QDoubleSpinBox for decimals
        severity_spinbox.setRange(0.0, 3.9)  # Set range from 0 to 3.9
        severity_spinbox.setSingleStep(0.01)  # Set the increment step to 0.01

        impact_combobox = QComboBox()
        impact_combobox.addItems(['NONE', 'LOW', 'HIGH'])

        form_layout.addWidget(QLabel("CVE ID:"))
        form_layout.addWidget(cve_id_edit)
        form_layout.addWidget(QLabel("Exploitability:"))
        form_layout.addWidget(severity_spinbox)
        form_layout.addWidget(QLabel("Impact:"))
        form_layout.addWidget(impact_combobox)
        
        cve_list_layout.addLayout(form_layout)
        cve_entries.append((cve_id_edit, severity_spinbox, impact_combobox))

    add_cve_button.clicked.connect(add_cve_entry)
    layout.addLayout(cve_list_layout)

    button_layout = QHBoxLayout()
    save_button = QPushButton("Save")
    cancel_button = QPushButton("Cancel")
    button_layout.addWidget(save_button)
    button_layout.addWidget(cancel_button)

    layout.addLayout(button_layout)

    def show_error_popup(message):
        error_popup = QMessageBox()
        error_popup.setIcon(QMessageBox.Critical)
        error_popup.setWindowTitle("Error")
        error_popup.setText(message)
        error_popup.exec()

    def save_device():
        cpe_name = cpe_name_edit.text().strip()
        if not cpe_name:
            show_error_popup("Please enter a CPE name.")
            return
        
        cve_list = []
        cve_ids = set()  # Keep track of unique CVE IDs

        for cve_id_edit, severity_spinbox, impact_combobox in cve_entries:
            cve_id = cve_id_edit.text().strip()
            severity = severity_spinbox.value()
            impact = impact_combobox.currentText()
            
            if cve_id:
                if cve_id in cve_ids:
                    show_error_popup("Please ensure CVE IDs have unique names.")
                    return
                cve_ids.add(cve_id)

                cve_info = [cve_id, severity, impact]
                status = True  # Default status to True (checked)
                cve_list.append((cve_info, status))

        deviceInfoList.append((cpe_name, cve_list))
        
        item = QListWidgetItem(cpe_name)
        results_list.addItem(item)
        results_to_device_map[len(deviceInfoList) - 1] = item
        
        dialog.accept()

        # Recalculate after adding a new device
        get_import_values()

    save_button.clicked.connect(save_device)
    cancel_button.clicked.connect(dialog.reject)

    dialog.exec()


def create_manual_layout(results_list):
    manual_layout = QVBoxLayout()

    add_device_button = QPushButton("Add Device")
    add_device_button.clicked.connect(lambda: handle_add_device(results_list))
    manual_layout.addWidget(add_device_button)

    search_button = QPushButton("Search")
    search_button.setEnabled(False)
    manual_layout.addWidget(search_button)

    return manual_layout
# =========================================================

def clear_devices(results_list):
    """
    Clears all devices from the list.
    """
    reply = QMessageBox.question(
        None, 'Clear All Devices',
        "Are you sure you want to clear all devices?",
        QMessageBox.Yes | QMessageBox.No,
        QMessageBox.No
    )
    if reply == QMessageBox.Yes:
        global deviceInfoList, results_to_device_map
        deviceInfoList.clear()
        results_to_device_map.clear()
        results_list.clear()
        update_pve_alt_button(0.00)

def setup_import_devices(container):
    """ 
    Configures the overall panel design and layout.
    """
    frame = QFrame(container)
    frame.setFrameShape(QFrame.Box)
    frame.setLineWidth(1)
    
    main_layout = QVBoxLayout(frame)

    # Top layout with dropdown and help button
    top_layout = QHBoxLayout()

    # Dropdown for Individual, Group, and Manual
    dropdown = QComboBox()
    dropdown.addItems(["Individual", "Group", "Manual"])  # Added "Manual"
    top_layout.addWidget(dropdown)

    # Help button
    help_button = QPushButton()
    help_button.setIcon(container.style().standardIcon(QStyle.SP_MessageBoxInformation))
    help_button.setFixedSize(20, 20)  # Adjust size
    help_button.clicked.connect(lambda: show_help_window(dropdown.currentText()))
    top_layout.addWidget(help_button)

    main_layout.addLayout(top_layout)

    # Stacked Layout for Individual, Group, and Manual views
    stacked_layout = QStackedLayout()

    results_list = create_results_list()

    individual_widget = QWidget()
    individual_layout = create_individual_layout(results_list)
    individual_widget.setLayout(individual_layout)
    stacked_layout.addWidget(individual_widget)

    group_widget = QWidget()
    group_layout = create_group_layout(container, results_list)
    group_widget.setLayout(group_layout)
    stacked_layout.addWidget(group_widget)
    
    manual_widget = QWidget()
    manual_layout = create_manual_layout(results_list)
    manual_widget.setLayout(manual_layout)
    stacked_layout.addWidget(manual_widget)

    def switch_view(index):
        stacked_layout.setCurrentIndex(index)

    dropdown.currentIndexChanged.connect(switch_view)
    main_layout.addLayout(stacked_layout)

    main_layout.addLayout(create_bottom_layout())
    main_layout.addWidget(results_list)

    # Clear Devices button and pVe_alt label
    clear_devices_button = QPushButton("Clear Devices")
    clear_devices_button.clicked.connect(lambda: clear_devices(results_list))
    main_layout.addWidget(clear_devices_button)

    global pve_alt_label
    pve_alt_label = QLabel("pVe_alt: 0.0000")
    main_layout.addWidget(pve_alt_label)  # Add pVe_alt label below the Clear Devices button

    container.setLayout(QVBoxLayout())
    container.layout().addWidget(frame)


def show_help_window(selection):
    """
    Creates the "Help Window" and subsequent text pertaining to each step.
    """
    help_text = {
        "Individual": """
1. Enter the name of the device in the entry field provided. For more accurate results, you can use the <a href='https://nvd.nist.gov/products/cpe/search'>NVD CPE database</a> to find the exact model name.<br><br>
2. Search for the device. By default, the result will be first found match. For a more refined search, use the <i>Detailed Search</i> checkbox. This will allow you to navigate a list of all potential matches for the given device name.<br>
&nbsp;&nbsp;&nbsp;&nbsp;a. If too many potential matches are found, you will be asked to provide more detail and try again.<br>
&nbsp;&nbsp;&nbsp;&nbsp;b. If no matches are found, you will be asked to redefine your search.<br>
<b>NOTE:</b> <i>Detailed Search is only recommended for advanced users.</i><br><br>
3. After a successful search, the <i>Imported Devices</i> dropdown will be populated with the found device. Double click the entry to modify its CVEs.<br>
&nbsp;&nbsp;&nbsp;&nbsp;a. By default, all CVEs less than 10 years old are enabled.<br>
&nbsp;&nbsp;&nbsp;&nbsp;b. Unchecking CVE checkboxes assumes the device has been "patched" and removes it from the final calculation.
        """,
        "Group": """
1. Before using this program, compile a list of devices in a text file. For more accurate results, you can use the <a href='https://nvd.nist.gov/products/cpe/search'>NVD CPE database</a> to find the exact model name.<br>
&nbsp;&nbsp;&nbsp;&nbsp;a. Place each device on a separate line.<br>
&nbsp;&nbsp;&nbsp;&nbsp;b. Lines that begin with "#" will not be read.<br><br>
2. Search for the devices. By default, the result will be first found match. For a more refined search, use the <i>Detailed Search</i> checkbox. This will allow you to navigate a list of all potential matches for the given device name.<br>
&nbsp;&nbsp;&nbsp;&nbsp;a. If too many potential matches are found, you will be asked to provide more detail and try again.<br>
&nbsp;&nbsp;&nbsp;&nbsp;b. If no matches are found, you will be asked to redefine your search.<br>
&nbsp;&nbsp;&nbsp;&nbsp;c. In the event of a detailed search, information is provided on your progress through the list and the number of repeat devices on the list.<br>
<b>NOTE:</b> <i>Detailed Search is only recommended for advanced users.</i><br><br>
3. After a successful search, the <i>Imported Devices</i> dropdown will be populated with the found device. Double click the entry to modify its CVEs.<br>
&nbsp;&nbsp;&nbsp;&nbsp;a. By default, all CVEs less than 10 years old are enabled.<br>
&nbsp;&nbsp;&nbsp;&nbsp;b. Unchecking CVE checkboxes assumes the device has been "patched" and removes it from the final calculation.
        """,
        "Manual": """
Use this if you want to manually create devices and CVEs. This section is mainly for testing or if the NVD API is down, using either an individual or group search is <b>highly recommended</b>.<br><br>

1. Create a device by clicking the <i>Add Device</i> button. This will bring you to a window where you can name your CPE (i.e., device). The name you give it will be displayed in the <i>Imported Devices</i> list once saved.<br><br>
2. Add CVEs to your device by clicking <i>Add CVE</i>. This will prompt you with a CVE ID, Exploitability score, and Impact.<br>
&nbsp;&nbsp;&nbsp;&nbsp;a. The CVE ID is displayed when clicking on the device in the <i>Imported Devices</i> list.<br>
&nbsp;&nbsp;&nbsp;&nbsp;b. Exploitability score and Impact directly affect the final cryptoperiod calculation. Exploitability must be between the bounds [0, 3.9].
        """
    }

    dialog = QDialog()
    dialog.setWindowTitle("Help")

    layout = QVBoxLayout()
    dialog.setLayout(layout)

    # Title
    if selection == "Individual":
        title = "Individual Search"
    elif selection == "Group":
        title = "Group Search"
    else:
        title = "Manual Entry"
    title_label = QLabel(title)
    title_label.setAlignment(Qt.AlignCenter)
    layout.addWidget(title_label)

    # Line under the title
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setFrameShadow(QFrame.Sunken)
    layout.addWidget(line)

    # Help text
    help_label = QLabel()
    help_label.setTextFormat(Qt.RichText)
    help_label.setText(help_text.get(selection, "No help available for this selection."))
    help_label.setOpenExternalLinks(True)
    help_label.setWordWrap(True)  # Ensure the text wraps within the window
    layout.addWidget(help_label)

    close_button = QPushButton("Close")
    ##close_button.setStyleSheet("background-color: #ADD8E6; border: none; color: white;")
    layout.addWidget(close_button)

    close_button.clicked.connect(dialog.accept)

    dialog.exec()

def get_import_values():
    """
    Calculates and returns the overall probability of software compromise.
    Updates the global display with the calculated compromise value
    Returns a tuple: (totalCompromise, True) if devices exist, otherwise (0, False)
    Used by show_results() in main.py.
    """
    if not deviceInfoList:
        print('No devices found')
        return 0, False

    activeDeviceInfoList = []
    for cpe, cves in deviceInfoList:
        active_cves = [(cve_info, status) for cve_info, status in cves if status]
        activeDeviceInfoList.append((cpe, active_cves))

    overallResilience = 1
    for cpe, cves in activeDeviceInfoList:
        deviceCompromise = calculate_resilience(cves)
        overallResilience *= 1 - deviceCompromise

    totalCompromise = 1 - overallResilience
    update_pve_alt_button(totalCompromise)  # Update the button with the new pVe_alt value

    return totalCompromise, True


def update_pve_alt_button(pVe_alt):
    """
    Updates the text for the probability of software compromise.
    Called whenever the probability of software compromised is changed.
    Original update_result_button() is defined in shared_functions.py.
    """
    global totalCompromiseDisplay
    update_result_button(totalCompromiseDisplay, pVe_alt, "Probability of Software Compromise")

def setup_import_devices(container):
    """
    Sets up the full device import UI section, including dropdown views and result display.
    Attaches a stacked layout to the container with individual, group, and manual device import modes.
    Adds functionality for clearing devices and displaying software compromise probability.
    """
    frame = QFrame(container)
    frame.setFrameShape(QFrame.Box)
    frame.setLineWidth(1)
    
    main_layout = QVBoxLayout(frame)

    # Top layout with dropdown and help button
    top_layout = QHBoxLayout()

    # Dropdown for Individual, Group, and Manual
    dropdown = QComboBox()
    dropdown.addItems(["Individual", "Group", "Manual"])  # Added "Manual"
    top_layout.addWidget(dropdown)

    # Help button
    help_button = QPushButton()
    help_button.setIcon(container.style().standardIcon(QStyle.SP_MessageBoxInformation))
    help_button.setFixedSize(20, 20)  # Adjust size
    help_button.clicked.connect(lambda: show_help_window(dropdown.currentText()))
    top_layout.addWidget(help_button)

    main_layout.addLayout(top_layout)

    # Stacked Layout for Individual, Group, and Manual views
    stacked_layout = QStackedLayout()

    results_list = create_results_list()

    individual_widget = QWidget()
    individual_layout = create_individual_layout(results_list)
    individual_widget.setLayout(individual_layout)
    stacked_layout.addWidget(individual_widget)

    group_widget = QWidget()
    group_layout = create_group_layout(container, results_list)
    group_widget.setLayout(group_layout)
    stacked_layout.addWidget(group_widget)
    
    manual_widget = QWidget()
    manual_layout = create_manual_layout(results_list)
    manual_widget.setLayout(manual_layout)
    stacked_layout.addWidget(manual_widget)

    def switch_view(index):
        stacked_layout.setCurrentIndex(index)

    dropdown.currentIndexChanged.connect(switch_view)
    main_layout.addLayout(stacked_layout)

    main_layout.addLayout(create_bottom_layout())
    main_layout.addWidget(results_list)

    clear_devices_button = QPushButton("Clear Devices")
    clear_devices_button.clicked.connect(lambda: [clear_devices(results_list), get_import_values()])
    main_layout.addWidget(clear_devices_button)

    global totalCompromiseDisplay
    totalCompromiseDisplay = create_result_button("#bababa")
    update_pve_alt_button(0.00) #set initial display
    main_layout.addWidget(totalCompromiseDisplay, alignment=Qt.AlignCenter)  # Add pVe_alt button below the Clear Devices button

    container.setLayout(QVBoxLayout())
    container.layout().addWidget(frame)