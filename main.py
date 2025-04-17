"""
Main Module.
Defines the location of each subset of UI elements (parameters_ui.py and import_devices_ui.py).
Performs the final cryptoperiod calculation based on values provided by:
- get_import_values (probability of software compromise)
- values
  - [0]: functional importance
  - [1]: information rate
  - [2]: policy strength
"""
from PySide6.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QFrame, QPushButton, QSizePolicy, QLineEdit, QMessageBox, QCheckBox, QMenuBar, QMenu
from PySide6.QtGui import QAction
from PySide6.QtCore import Qt
import sys
from parameters_ui import setup_top_right, setup_impact, update_time_difference, values
from import_devices_ui import setup_import_devices, get_import_values

results_text_box = None
show_message_box = True  # do not show again

def empty_import(variable):
    """
    Detects if no devices are imported. If so, provide a warning.
    """
    global show_message_box

    if not variable and show_message_box:

        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setText("Without any imported devices, the calculation will assume the worst case scenario in which the probability of an exploit is guaranteed. Do you want to continue?")
        msg_box.setWindowTitle("No Imported Devices")
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.No)
        
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        checkbox = QCheckBox("Do not show again")
        main_layout.addWidget(checkbox)
        msg_box.layout().addWidget(main_widget, 1, 0, 1, msg_box.layout().columnCount())

        reply = msg_box.exec()
        
        # do not show checkbox
        if checkbox.isChecked():
            show_message_box = False

        return reply == QMessageBox.Yes
    return True

def show_cryptoperiod_warning():
    """
    Defines warning if there is an error regarding the minimum or maximum cryptoperiod values.
    Used in show_results().
    """
    # Create a message box
    msg_box = QMessageBox()
    
    # Set the icon and message for the warning
    msg_box.setIcon(QMessageBox.Warning)
    msg_box.setWindowTitle("Error")
    msg_box.setText("Minimum cryptoperiod time must be smaller than the maximum cryptoperiod time.")
    
    # Set the OK button
    msg_box.setStandardButtons(QMessageBox.Ok)
    
    # Execute the message box and wait for user response
    msg_box.exec()

def display_time_difference(hours):
    """
    Formats the time for the final cryptoperiod calculation display.
    """

    months = hours // (30 * 24)
    hours %= (30 * 24)
    days = hours // 24
    hours %= 24
    minutes = (hours - int(hours)) * 60
    hours = int(hours)

    months = int(months)
    days = int(days)
    hours = int(hours)
    minutes = int(minutes)

    result = []
    if months > 0:
        result.append(f"{months} month{'s' if months != 1 else ''}")
    if days > 0 or (months > 0 and (hours > 0 or minutes > 0)):
        result.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0 or (days > 0 or months > 0) and minutes > 0:
        result.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0 or hours > 0 or days > 0 or months > 0:
        result.append(f"{minutes} minute{'s' if minutes != 1 else ''}")

    return ", ".join(result)

def show_results():
    """
    Actual calculation for the overal cryptoperiod.
    Also displays cryptoperiod and individual variable calculations in console.
    """

    deviceProbability, isNotEmpty = get_import_values()
    timeRange1, timeRange2 = update_time_difference()

    if timeRange1 > timeRange2:
        show_cryptoperiod_warning()
        return
    
    if not empty_import(isNotEmpty): # Create warning pop-up if no devices are present
        return
            
    if deviceProbability == 0: #if no devices, assume worst case scenario
      deviceProbability = 1
      
    # === FINAL FORMULA ===
    probability = 1 - ((1 - deviceProbability)*(1 - values.policy))
    print(f'Software Probability: {deviceProbability}   Procedure Probability: {values.policy}\nTOTAL PROBABILITY: {probability}') 

    weight = 1 - (values.impact ** (1/3))
    impact = values.impact * values.information**weight
    print(f'Information Rate: {values.information}   Functional Importance: {values.impact}\nTOTAL IMPACT: {impact}')

    
    finalRisk = (probability * impact)

    print(f"Final Risk: {finalRisk}\n")
    
    cryptoperiod = timeRange1 * (timeRange2 / timeRange1)**(1-finalRisk)
    cryptoperiod_display = "Old: " + display_time_difference(cryptoperiod)

    if results_text_box:
        results_text_box.setText(f" {cryptoperiod_display}")
        print(f"Recommended cryptoperiod: {cryptoperiod_display}\n")
    # =====================
    
def create_main_window():
    """
    Creates the main window using defined objects from parameters_ui.py and import_devices_ui.py.
    """
    window = QMainWindow()
    window.setWindowTitle("ARC-C Cryptoperiod Calculator")

    container = QWidget()
    main_layout = QVBoxLayout(container)
    main_layout.setAlignment(Qt.AlignTop)  # Align the main layout to the top

    # Create a top frame and set up the top UI in it
    top_frame = QFrame()
    top_layout = QHBoxLayout(top_frame)

    left_container = QFrame()
    setup_import_devices(left_container)
    top_layout.addWidget(left_container)

    right_container = QFrame()
    setup_top_right(right_container)
    top_layout.addWidget(right_container)

    top_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    main_layout.addWidget(top_frame, alignment=Qt.AlignTop)

    # Create a bottom frame and set up the right UI in it
    bottom_frame = QFrame()
    setup_impact(bottom_frame)
    bottom_frame.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    main_layout.addWidget(bottom_frame, alignment=Qt.AlignTop)

    # Create a horizontal layout for the print button and text box
    button_text_layout = QHBoxLayout()

    # Create the print button
    print_button = QPushButton("Calculate Cryptoperiod")
    print_button.setFixedHeight(30)
    print_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    print_button.setToolTip("This button prints the results.")
    print_button.clicked.connect(show_results)
    print_button.setStyleSheet("background-color: #1E90FF; color: white; border-radius: 3px;")
    button_text_layout.addWidget(print_button, 1)

    # Create the uneditable text box
    global results_text_box
    results_text_box = QLineEdit()
    results_text_box.setReadOnly(True)
    results_text_box.setFixedHeight(30)
    results_text_box.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
    button_text_layout.addWidget(results_text_box, 4)

    # Add the horizontal layout to the main layout
    main_layout.addLayout(button_text_layout)

    container.setLayout(main_layout)
    window.setCentralWidget(container)
    return window

def main():
    global app
    app = QApplication(sys.argv)
    window = create_main_window()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()