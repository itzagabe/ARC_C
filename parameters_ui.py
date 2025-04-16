"""
Module for defining the specific functionality for the radio buttons.
Builds off the base logic defined in parameters_logic.py.
"""
from PySide6.QtWidgets import (
    QVBoxLayout, QHBoxLayout, QWidget,
    QFrame, QSizePolicy, QToolButton, QLabel, QSpinBox, QComboBox, QSpacerItem
)
from PySide6.QtCore import Qt
from parameters_logic import display_results, create_layout
from shared_functions import interpolate_colour, create_result_button

# === Colour Definitions ===
low = "#90EE90"  # Low
medium = "#ffd68b"  # Medium
high = "#f09d9d"  # High
critical = "#e47676"  # High


class Values:
    """
    Class containing functional importance (impact), information rate (information) and policy strength (policy) values.
    Used in main.py to calcuate the final cryptoperiod along with get_import_values() from import_devices_ui.py.
    """
    impact = 0
    information = 0.1
    policy = 1 # do the inverse of the policy rating for initial value, IE policy strength of 0 means policy = 1

values = Values()

def create_generic_layout(severityList, categoryList, numButtonGroups, updateFunc, defaultColor, tooltips, createResultButton):
    """
    Generates a reusable vertical layout that includes grouped toggle buttons (severity selectors) for different categories. 
    Each group represents a set of mutually exclusive toggle buttons indicating levels of severity (e.g., None, Low, Medium, High).

    The layout dynamically updates a result display (if enabled) based on the user's selections.
    - severityList: List of tuples specifying (label, score, color) for each 
      severity level.
    - categoryList: List of category names or (name, subcategories) tuples 
      specifying the layout structure.
    - numButtonGroups: Number of grouped buttons per category.
    - updateFunc: Function to handle logic for computing and updating the result.
    - defaultColor: Default background color for the result display.
    - tooltips: Dictionary mapping label names to tooltip text.
    - createResultButton: Boolean flag to indicate whether to add a result 
      display button to the layout.

    See the "Initalize category varaibles" section in this file for examples on how to implement a layout.
    """
    
    def update_button(buttonGroups, activeItems, resultButton=None):
        returnValue = display_results(buttonGroups, activeItems)
        updateFunc(returnValue, resultButton)

    def connect_button(buttonGroups, activeItems, resultButton, uiFrame):
        for buttonGroupDict in buttonGroups:
            for buttonGroup in buttonGroupDict.values():
                buttonGroup.buttonToggled.connect(lambda: update_button(buttonGroups, activeItems, resultButton))
        for btn in uiFrame.findChildren(QToolButton):
            btn.toggled.connect(lambda: update_button(buttonGroups, activeItems, resultButton))

    mainLayout = QVBoxLayout()
    mainLayout.setSpacing(10)
    mainLayout.setContentsMargins(0, 0, 0, 0)
    
    uiFrame = QFrame()
    uiLayout = QVBoxLayout(uiFrame)
    uiLayout.setAlignment(Qt.AlignTop | Qt.AlignLeft)
    uiLayout.setSpacing(10)
    uiLayout.setContentsMargins(0, 0, 0, 0)
    uiFrame.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

    buttonGroups, activeItems = create_layout(uiLayout, severityList, categoryList, numButtonGroups)

    def set_tooltips(widget, tooltips):
      """
      Logic to define tooltips for each label.
      """
      for child in widget.findChildren(QWidget):
          if isinstance(child, QLabel):
              labelText = child.text().strip()
              if labelText in tooltips:
                  child.setToolTip(tooltips[labelText])
          set_tooltips(child, tooltips)

    set_tooltips(uiFrame, tooltips)

    if createResultButton:
        resultButton = create_result_button(defaultColor)
        update_button(buttonGroups, activeItems, resultButton)
        connect_button(buttonGroups, activeItems, resultButton, uiFrame)
        uiLayout.addWidget(resultButton, alignment=Qt.AlignTop | Qt.AlignHCenter)
    else:
        connect_button(buttonGroups, activeItems, None, uiFrame)

    return uiFrame

# === Initalize category varaibles ===
def impact_categories():
    """
    Initializes the functional importance variables to use for create_generic_layout
    """
    severityList = [("None", 0, "#bababa"), ("Low", 0.3, low), ("Medium", 0.6, medium), ("High", 1, high), ("Critical", 2, critical)]
    categoryList = [
        ("Operational", []), ("Safety", []), ("Financial", []),
        ("Privacy and Legislative", [])
    ]
    tooltips = {
        "Operational": "Disruptions caused by adversaries accessing sensitive data within the ICS environment ", 

        "Safety": "Information about safety protocols, emergency response plans, or control settings of safety-critical systems",

        "Financial": "Economic repercussions that result from the compromise of data within an organization",

        "Privacy and Legislative": "Consequences of adversaries gaining access to sensitive personal information and compliance-related data",

    }

    return create_generic_layout(severityList, categoryList, 2, update_impact_layout, "#bababa", tooltips, True)

def information_rate_categories():
    """
    Initializes the information rate variables to use for create_generic_layout
    """
    severityList = [("Low", 1, low), ("Medium", 2, medium), ("High", 3, high)]
    categoryList = ['Data Rate', 'Publishers']
    tooltips = {"Data Rate": "Average amount of data sent per publisher", "Publishers": "Number of publishers in the environment"}

    return create_generic_layout(severityList, categoryList, 1, update_information_rate_layout, "#90EE90", tooltips, True)

def policy_categories():
    """
    Initializes the policy strength variables to use for create_generic_layout
    """
    severityList = [("None", 1, "#bababa"), ("Low", 0.75, low), ("Medium", 0.45, medium), ("High", 0.1, high)] # CHANGED None and High
    tooltips = {"Policy Strength": "How strong are security-related procedural policies and guidelines"}

    return create_generic_layout(severityList, ['Policy Strength'], 1, update_policy_layout, "#bababa", tooltips, False)
# ====================================

# === Apply Unique Characteristics to category variables ===
def update_impact_layout(returnValue, resultButton):
    """
    Extra impelementation for functional importance.
    """
    from collections import defaultdict
    
    # Group scores by category
    category_scores = defaultdict(list)
    for group, category, rating, score in returnValue:
        category_scores[category].append(score)
    
    # Multiply scores for each category
    multiplied_scores = []
    for scores in category_scores.values():
        product = 1
        for score in scores:
            product *= score
        multiplied_scores.append(product)
    
    # Calculate the final average severity score
    impactExtent = sum(multiplied_scores) / len(multiplied_scores) if multiplied_scores else 0
    
    colors = [(0, "#bababa"), (0.3, low), (0.6, medium), (1, high)]
    
    for i in range(len(colors) - 1):
        if colors[i][0] <= impactExtent <= colors[i + 1][0]:
            factor = (impactExtent - colors[i][0]) / (colors[i + 1][0] - colors[i][0])
            color = interpolate_colour(colors[i][1], colors[i + 1][1], factor)
            break
    else:
        color = colors[-1][1]

    impactExtent = min(impactExtent, 1)

    resultButton.setText(f"Impact Extent: {impactExtent:.2f}")
    resultButton.setStyleSheet(f"background-color: {color}; border-radius: 3px; color: black;")
    if impactExtent > 1:
        impactExtent = 1
    values.impact = round(impactExtent, 2)

def update_information_rate_layout(returnValue, resultButton):
    """
    Extra impelementation for information rate.
    """
    severityLabel, severityValue = map_information_rate_categories(returnValue)
    colorMap = {"Very Low": "#d4f1d4", "Low": low, "Moderate": medium, "High": high, "Very High": "#f28888"}
    color = colorMap.get(severityLabel, "#FFFFFF")
    resultButton.setText(f"{severityLabel} ({severityValue})")
    resultButton.setStyleSheet(f"background-color: {color}; border-radius: 3px; color: black;")
    values.information = severityValue


def map_information_rate_categories(returnValue):
    """
    Defined implementation for the information rate mapping.
    Used in the update_information_rate_layout() of parameters_ui.py.
    """
    severityMap = {"Low": 0, "Medium": 1, "High": 2}

    if len(returnValue) < 2:
        return "Incomplete data"

    # Automatically assign the first and second categories
    informationRateLevel = returnValue[0][2]
    publishersLevel = returnValue[1][2]

    informationRateIndex = severityMap.get(informationRateLevel)
    publishersIndex = severityMap.get(publishersLevel)

    if informationRateIndex is None or publishersIndex is None:
        return "Invalid severity level"

    chart = [
        [["Very Low", 0.1], ["Low", 0.3], ["Moderate", 0.75]],
        [["Low", 0.3], ["Moderate", 0.75], ["High", 0.9]],
        [["Moderate", 0.75], ["High", 0.9], ["Very High", 1.0]]
    ]

    result = chart[publishersIndex][informationRateIndex]

    return result
    
def update_policy_layout(returnValue, resultButton):
    """
    Defined implementation for the policy mapping.
    Used in the update_policy_layout() of parameters_ui.py.
    """
    values.policy = returnValue[0][3] # inverse as smaller number = less risk
# ==========================================================

def setup_ui(container):
    """ 
    Configures the overall panel design and layout.
    """
    impactFrame = impact_categories()
    dataFrame = information_rate_categories()
    policyFrame = policy_categories()
    
    mainLayout = QHBoxLayout()
    mainLayout.setSpacing(10)
    mainLayout.setContentsMargins(0, 0, 0, 0)
    mainLayout.setAlignment(Qt.AlignTop)

    leftLayout = QVBoxLayout()
    leftLayout.setSpacing(10)
    leftLayout.setAlignment(Qt.AlignTop)
    
    leftLayout.addWidget(policyFrame)
    
    dataContainer = QFrame()
    dataContainerLayout = QVBoxLayout(dataContainer)
    dataContainerLayout.setAlignment(Qt.AlignLeft)
    dataContainerLayout.addWidget(dataFrame)
    leftLayout.addWidget(dataContainer)

    rightLayout = QVBoxLayout()
    rightLayout.setSpacing(10)
    rightLayout.setAlignment(Qt.AlignTop)
    
    rightContainer = QFrame()
    rightContainerLayout = QVBoxLayout(rightContainer)
    rightContainerLayout.setAlignment(Qt.AlignLeft)
    rightContainerLayout.addWidget(impactFrame)
    rightLayout.addWidget(rightContainer)

    mainLayout.addLayout(leftLayout)
    mainLayout.addLayout(rightLayout)
    
    container.setLayout(mainLayout)

#### I added the slider logic here cause it was easier

def create_time_range_input(label_text, update_function, default_value=1, default_unit="hours"):
    timeRangeLayout = QVBoxLayout()
    timeRangeLabel = QLabel(label_text)
    timeRangeLabel.setAlignment(Qt.AlignLeft)
    timeRangeInputLayout = QHBoxLayout()
    timeRangeSpinBox = QSpinBox()
    timeRangeSpinBox.setRange(1, 1000)
    timeRangeSpinBox.setValue(default_value)  # Set default spinbox value
    timeRangeSpinBox.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
    timeRangeComboBox = QComboBox()
    timeRangeComboBox.addItems(["hours", "days", "months"])
    timeRangeComboBox.setCurrentText(default_unit)  # Set default combobox value
    timeRangeComboBox.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
    timeRangeSpinBox.valueChanged.connect(lambda value: update_function(value, timeRangeComboBox.currentText()))
    timeRangeComboBox.currentTextChanged.connect(lambda unit: update_function(timeRangeSpinBox.value(), unit))
    timeRangeInputLayout.addWidget(timeRangeSpinBox, 1)
    timeRangeInputLayout.addWidget(timeRangeComboBox, 2)
    timeRangeLayout.addWidget(timeRangeLabel)
    timeRangeLayout.addLayout(timeRangeInputLayout)

    update_function(default_value, default_unit)
    
    return timeRangeLayout

def setup_top_right(container):
    policyFrame = policy_categories()
    dataFrame = information_rate_categories()

    leftLayout = QVBoxLayout()
    leftLayout.setSpacing(10)
    leftLayout.setAlignment(Qt.AlignTop)

    timeText = "Choose the shortest and longest acceptable cryptoperiod for your \ngiven environment."
    timeLabel = QLabel(timeText)
    timeLabel.setAlignment(Qt.AlignLeft)
    leftLayout.addWidget(timeLabel)

    timeRange1Layout = create_time_range_input("Minimum:", update_time_range_1, default_value=1, default_unit="days")  # Set default to 1 day
    timeRange2Layout = create_time_range_input("Maximum:", update_time_range_2, default_value=12, default_unit="months")  # Set default to 12 months
    timeRangesLayout = QHBoxLayout()
    timeRangesLayout.addLayout(timeRange1Layout)
    timeRangesLayout.addLayout(timeRange2Layout)

    leftLayout.addLayout(timeRangesLayout)

    policyText = "\n\nHow strong are security-related procedural policies and guidelines?"
    policyLabel = QLabel(policyText)
    policyLabel.setAlignment(Qt.AlignLeft)
    leftLayout.addWidget(policyLabel)
    leftLayout.addWidget(policyFrame)

    dataText = "\n\nWhat is the amount of unique data being transmitted?"
    dataLabel = QLabel(dataText)
    dataLabel.setAlignment(Qt.AlignLeft)
    leftLayout.addWidget(dataLabel)

    dataFrameLayout = QVBoxLayout()
    dataFrameLayout.setContentsMargins(25, 0, 0, 0)  # Adjust the values as needed
    dataFrameLayout.addWidget(dataFrame)

    leftLayout.addLayout(dataFrameLayout)

    container.setLayout(leftLayout)

def setup_impact(container):
    impactFrame = impact_categories()
    
    rightLayout = QVBoxLayout()
    rightLayout.setSpacing(10)
    rightLayout.setAlignment(Qt.AlignTop)

    impactText = "Choose the impact of the group data in the event of a compromise. Importance measures how critical a function is to your organization's success. \nExtent measures the actual consequences to a function in the event of an incident.\n"
    impactLabel = QLabel(impactText)
    impactLabel.setAlignment(Qt.AlignLeft)
    rightLayout.addWidget(impactLabel)

    # Create a horizontal layout for the Importance and Extent labels
    labelLayout = QHBoxLayout()

    # Spacer item to the left of Importance label with a fixed width
    spacer_before_importance = QSpacerItem(215, 0, QSizePolicy.Fixed, QSizePolicy.Minimum)
    labelLayout.addItem(spacer_before_importance)

    # Importance label
    importanceLabel = QLabel("Functional Impact on Different Functions")
    importanceLabel.setToolTip("Impact extent [Data Siphoning] on each organizational function")
    labelLayout.addWidget(importanceLabel)

    # Spacer item to the left of Extent label with a fixed width
    spacer_before_extent = QSpacerItem(75, 0, QSizePolicy.Fixed, QSizePolicy.Minimum)
    labelLayout.addItem(spacer_before_extent)

    # Extent label
    extentLabel = QLabel("Criticality on Different Functions")
    extentLabel.setToolTip("Importance of each organizational function on company's overall performance")
    labelLayout.addWidget(extentLabel)

    # Add the label layout to the right layout
    rightLayout.addLayout(labelLayout)
    
    rightContainer = QFrame()
    rightContainerLayout = QVBoxLayout(rightContainer)
    rightContainerLayout.setAlignment(Qt.AlignLeft)
    rightContainerLayout.addWidget(impactFrame)
    rightLayout.addWidget(rightContainer)

    container.setLayout(rightLayout)

# Define global variable
global timeDifference
timeDifference = 0

# Define non-global variables to keep track of time ranges
timeRange1 = 1
timeRange2 = 1

def update_time_range_1(value, unit):
    global timeRange1
    timeRange1 = convert_to_hours(value, unit)
    update_time_difference()
    #print(f"Time Range 1: {time_range1_hours} hours")

def update_time_range_2(value, unit):
    global timeRange2
    timeRange2 = convert_to_hours(value, unit)
    update_time_difference()
    #print(f"Time Range 2: {time_range2_hours} hours")

def update_time_difference():
    global timeDifference
    timeDifference = abs(timeRange2 - timeRange1)
    #print(f"Time Difference: {timeDifference} hours")
    return timeRange1, timeRange2

def convert_to_hours(value, unit):
    if unit == "hours":
        return value
    elif unit == "days":
        return value * 24
    elif unit == "months":
        return value * 30 * 24  # Approximate month as 30 days
