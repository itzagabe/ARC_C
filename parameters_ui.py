import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget,
    QFrame, QSizePolicy, QToolButton, QLabel, QSlider, QSpinBox, QComboBox, QSpacerItem
)
from PySide6.QtCore import Qt
from parameters_logic import DisplayResults, CreateLayout, MapDataCategories
from shared_functions import InterpolateColour, CreateResultButtonWidget

low = "#90EE90"  # Low
medium = "#ffd68b"  # Medium
high = "#f09d9d"  # High
critical = "#e47676"  # High

#defaultPolicyRating = 0 # change this for default policy rating, NOTE the lower the number the "weaker" the policy strength, PVE-proc is 1 - policyRating

class Values:
    impact = 0
    data = 0.1
    policy = 1 #do the inverse of the policy rating for initial value

values = Values()

def SetTooltips(widget, tooltips):
    for child in widget.findChildren(QWidget):
        if isinstance(child, QLabel):
            labelText = child.text().strip()
            if labelText in tooltips:
                child.setToolTip(tooltips[labelText])
        SetTooltips(child, tooltips)

def CreateGenericLayout(severityList, categoryList, numButtonGroups, updateFunc, defaultColor, tooltips, createResultButton):
    
    def UpdateButton(buttonGroups, activeItems, resultButton=None):
        returnValue = DisplayResults(buttonGroups, activeItems)
        updateFunc(returnValue, resultButton)

    def ConnectButtons(buttonGroups, activeItems, resultButton, uiFrame):
        for buttonGroupDict in buttonGroups:
            for buttonGroup in buttonGroupDict.values():
                buttonGroup.buttonToggled.connect(lambda: UpdateButton(buttonGroups, activeItems, resultButton))
        for btn in uiFrame.findChildren(QToolButton):
            btn.toggled.connect(lambda: UpdateButton(buttonGroups, activeItems, resultButton))

    mainLayout = QVBoxLayout()
    mainLayout.setSpacing(10)
    mainLayout.setContentsMargins(0, 0, 0, 0)
    
    uiFrame = QFrame()
    uiLayout = QVBoxLayout(uiFrame)
    uiLayout.setAlignment(Qt.AlignTop | Qt.AlignLeft)
    uiLayout.setSpacing(10)
    uiLayout.setContentsMargins(0, 0, 0, 0)
    uiFrame.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

    buttonGroups, activeItems = CreateLayout(uiLayout, severityList, categoryList, numButtonGroups)
    SetTooltips(uiFrame, tooltips)

    if createResultButton:
        resultButton = CreateResultButtonWidget(defaultColor)
        UpdateButton(buttonGroups, activeItems, resultButton)
        ConnectButtons(buttonGroups, activeItems, resultButton, uiFrame)
        uiLayout.addWidget(resultButton, alignment=Qt.AlignTop | Qt.AlignHCenter)
    else:
        ConnectButtons(buttonGroups, activeItems, None, uiFrame)

    return uiFrame

def UpdateImpactLayout(returnValue, resultButton):
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
            color = InterpolateColour(colors[i][1], colors[i + 1][1], factor)
            break
    else:
        color = colors[-1][1]

    impactExtent = min(impactExtent, 1)

    resultButton.setText(f"Impact Extent: {impactExtent:.2f}")
    resultButton.setStyleSheet(f"background-color: {color}; border-radius: 3px; color: black;")
    if impactExtent > 1:
        impactExtent = 1
    values.impact = round(impactExtent, 2)

def UpdateDataLayout(returnValue, resultButton):
    severityLabel, severityValue = MapDataCategories(returnValue)
    colorMap = {"Very Low": "#d4f1d4", "Low": low, "Moderate": medium, "High": high, "Very High": "#f28888"}
    color = colorMap.get(severityLabel, "#FFFFFF")
    resultButton.setText(f"{severityLabel} ({severityValue})")
    resultButton.setStyleSheet(f"background-color: {color}; border-radius: 3px; color: black;")
    values.data = severityValue
    
def UpdatePolicyLayout(returnValue, resultButton):
    values.policy = returnValue[0][3] # inverse as smaller number = less risk

def ImpactCategories():
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

    return CreateGenericLayout(severityList, categoryList, 2, UpdateImpactLayout, "#bababa", tooltips, True)
# def ImpactCategories():
#     severityList = [("None", 0, "#bababa"), ("Low", 0.3, low), ("Medium", 0.6, medium), ("High", 1, high), ("Critical", 2, critical)]
#     categoryList = [
#         ("Operational", []), ("Safety", []), ("Financial", ["Loss of Revenue", "Proprietary Information", "Legal Fees"]),
#         ("Privacy and Legislative", ["Societal Loss", "Regulatory Loss", "Environmental Loss"])
#     ]
#     tooltips = {
#         "Operational": "Disruptions caused by adversaries accessing sensitive data within the ICS environment ", 

#         "Safety": "Information about safety protocols, emergency response plans, or control settings of safety-critical systems",

#         "Financial": "Economic repercussions that result from the compromise of data within an organization",
#         "Loss of Revenue": "Financial setbacks resulting from disruptions to control system operations, devices, and processes",
#         "Proprietary Information": "Financial loss from the compromises of both intellectual property and trade secrets",
#         "Legal Fees": "Cost associated with defending against lawsuits",

#         "Privacy and Legislative": "Consequences of adversaries gaining access to sensitive personal information and compliance-related data",
#         "Societal Loss": "Repercussions on communities and public trust, encompassing factors related to public perception",
#         "Regulatory Loss": "Affect an attack can have on the environment",
#         "Environmental Loss": "Losses due to legal and regulatory aspects, including legal penalties and fines"
#     }

#     return CreateGenericLayout(severityList, categoryList, 2, UpdateImpactLayout, "#bababa", tooltips, True)

def DataCategories():
    severityList = [("Low", 1, low), ("Medium", 2, medium), ("High", 3, high)]
    categoryList = ['Data Rate', 'Publishers']
    tooltips = {"Data Rate": "Average amount of data sent per publisher", "Publishers": "Number of publishers in the environment"}

    return CreateGenericLayout(severityList, categoryList, 1, UpdateDataLayout, "#90EE90", tooltips, True)

def PolicyCategories():
    severityList = [("None", 1, "#bababa"), ("Low", 0.75, low), ("Medium", 0.45, medium), ("High", 0.1, high)] # CHANGED None and High
    tooltips = {"Policy Strength": "How strong are security-related procedural policies and guidelines"}

    return CreateGenericLayout(severityList, ['Policy Strength'], 1, UpdatePolicyLayout, "#bababa", tooltips, False)

def main():
    app = QApplication(sys.argv)
    window = QMainWindow()
    window.setWindowTitle("Main UI")

    impactFrame = ImpactCategories()
    dataFrame = DataCategories()
    policyFrame = PolicyCategories()
    
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
    
    container = QWidget()
    container.setLayout(mainLayout)
    window.setCentralWidget(container)

    printButton = QPushButton("Print Values")
    printButton.setFixedHeight(30)
    printButton.setFixedWidth(100)
    printButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    printButton.setToolTip("This button prints the values list.")
    printButton.clicked.connect(lambda: print(values))
    
    mainLayout.addWidget(printButton, alignment=Qt.AlignBottom | Qt.AlignRight)

    window.show()
    sys.exit(app.exec())

def setup_ui(container):
    impactFrame = ImpactCategories()
    dataFrame = DataCategories()
    policyFrame = PolicyCategories()
    
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

def createTimeRangeInput(label_text, update_function, default_value=1, default_unit="hours"):
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

def setupTopRight(container):
    policyFrame = PolicyCategories()
    dataFrame = DataCategories()

    leftLayout = QVBoxLayout()
    leftLayout.setSpacing(10)
    leftLayout.setAlignment(Qt.AlignTop)

    timeText = "Choose the shortest and longest acceptable cryptoperiod for your \ngiven environment."
    timeLabel = QLabel(timeText)
    timeLabel.setAlignment(Qt.AlignLeft)
    leftLayout.addWidget(timeLabel)

    timeRange1Layout = createTimeRangeInput("Minimum:", updateTimeRange1, default_value=1, default_unit="days")  # Set default to 1 day
    timeRange2Layout = createTimeRangeInput("Maximum:", updateTimeRange2, default_value=12, default_unit="months")  # Set default to 12 months
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

# Define global variable
global timeDifference
timeDifference = 0

# Define non-global variables to keep track of time ranges
timeRange1 = 1
timeRange2 = 1

def updateTimeRange1(value, unit):
    global timeRange1
    timeRange1 = convertToHours(value, unit)
    updateTimeDifference()
    #print(f"Time Range 1: {time_range1_hours} hours")

def updateTimeRange2(value, unit):
    global timeRange2
    timeRange2 = convertToHours(value, unit)
    updateTimeDifference()
    #print(f"Time Range 2: {time_range2_hours} hours")

def updateTimeDifference():
    global timeDifference
    timeDifference = abs(timeRange2 - timeRange1)
    #print(f"Time Difference: {timeDifference} hours")
    return timeRange1, timeRange2

def convertToHours(value, unit):
    if unit == "hours":
        return value
    elif unit == "days":
        return value * 24
    elif unit == "months":
        return value * 30 * 24  # Approximate month as 30 days
    

def setupImpact(container):
    impactFrame = ImpactCategories()
    
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

    # # Reintroduced commented-out code
    # printButton = QPushButton("Print Values")
    # printButton.setFixedHeight(30)
    # printButton.setFixedWidth(100)
    # printButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    # printButton.setToolTip("This button prints the values list.")
    # printButton.clicked.connect(lambda: print(values))

    # mainLayout.addWidget(printButton, alignment=Qt.AlignBottom | Qt.AlignRight)


if __name__ == "__main__":
    main()
