import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QLabel, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QButtonGroup, QToolButton, QFrame
from PySide6.QtCore import Qt
from shared_functions import InterpolateColour

def ButtonGroup(severityList):
    buttonGroup = QButtonGroup()
    buttonLayout = QHBoxLayout()
    buttonLayout.setSpacing(0)

    for i, (label, value, colour) in enumerate(severityList):
        button = QPushButton(label)
        button.setFixedSize(60, 30)
        button.setCheckable(True)
        button.setProperty('severity_value', value)
        button.setProperty('severity_color', colour)
        button.setStyleSheet(f"QPushButton {{ border-radius: 0px; background-color: lightgray; }} QPushButton:checked {{ background-color: {colour}; }} QPushButton:checked:disabled {{ background-color: gray; }} QPushButton:disabled:!checked {{ background-color: darkgray; }}")
        if i == 0:
            button.setStyleSheet(button.styleSheet() + "QPushButton { border-top-left-radius: 3px; border-bottom-left-radius: 3px; }")
            button.setChecked(True)
        if i == len(severityList) - 1:
            button.setStyleSheet(button.styleSheet() + "QPushButton { border-top-right-radius: 3px; border-bottom-right-radius: 3px; }")
        buttonGroup.addButton(button)
        buttonLayout.addWidget(button)
           
    return buttonGroup, buttonLayout

def CatLayout(mainLayout, buttonGroupsList, categoryList, severityList):
    if isinstance(categoryList, str):
        categoryList = [(categoryList, [])]
    elif isinstance(categoryList, list):
        categoryList = [(item, []) if isinstance(item, str) else item for item in categoryList]
    activeItems = None
    if any(subcategories for _, subcategories in categoryList):
        activeItems = []

    for categoryName, subcategories in categoryList:
        if activeItems is not None:
            activeItems.append(categoryName)  # By default, main categories are active
        categoryLayout = QHBoxLayout()

        # Frame for dropdown button and category/subcategory labels
        frameLabels = QFrame()
        layoutLabels = QVBoxLayout()
        layoutLabels.setSpacing(0)
        layoutLabels.setContentsMargins(0, 4, 0, 0)
        frameLabels.setLayout(layoutLabels)

        frames = []
        layouts = []

        for _ in buttonGroupsList:
            frame = QFrame()
            layout = QVBoxLayout()
            layout.setSpacing(0)
            layout.setContentsMargins(0, 4, 0, 0)
            frame.setLayout(layout)
            frames.append(frame)
            layouts.append(layout)

        if subcategories:
            toggleButton = QToolButton()
            toggleButton.setText('▶')
            toggleButton.setCheckable(True)
            toggleButton.setChecked(False)
            toggleButton.setToolButtonStyle(Qt.ToolButtonIconOnly)
            toggleButton.setArrowType(Qt.RightArrow)
            toggleButton.toggled.connect(lambda checked, btn=toggleButton, cat=categoryName, subs=subcategories, label=frameLabels: ToggleSubcat(checked, btn, cat, subs, activeItems, categoryList, buttonGroupsList, label))
            categoryLayout.addWidget(toggleButton)
        else:
            dropdownSpacer = QWidget()
            dropdownSpacer.setFixedWidth(20)  # Dropdown button width for alignment
            categoryLayout.addWidget(dropdownSpacer)

        if not subcategories:
            categoryName = " " + categoryName  # Add a leading space for categories without subcategories
        categoryLabel = QLabel(categoryName)
        categoryLabel.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        layoutLabels.addWidget(categoryLabel)  # Line determining location of the label

        for layout, buttonGroups in zip(layouts, buttonGroupsList):
            buttonGroup, buttonLayout = ButtonGroup(severityList)
            layout.addLayout(buttonLayout)
            buttonGroups[categoryName.strip()] = buttonGroup

        categoryLayout.addWidget(frameLabels)
        for frame in frames:
            categoryLayout.addWidget(frame)

        mainLayout.addLayout(categoryLayout)

        if subcategories:
            subcategoryFrame = QFrame()
            subcategoryFrame.setFrameShape(QFrame.NoFrame)
            subcategoryLayout = QVBoxLayout()
            subcategoryLayout.setSpacing(0)
            subcategoryLayout.setContentsMargins(20, 0, 0, 0)

            for subcategory in subcategories:
                subcategoryLayout.addLayout(SubcatLayout(subcategory, severityList, buttonGroupsList, categoryName.strip()))

            subcategoryFrame.setLayout(subcategoryLayout)
            subcategoryFrame.setVisible(False)
            mainLayout.addWidget(subcategoryFrame)
            toggleButton.toggled.connect(lambda checked, frame=subcategoryFrame: frame.setVisible(checked))

    return activeItems

def ToggleSubcat(checked, button, categoryName, subcategories, activeItems, categoryList, buttonGroupsList, label):
    if checked:
        if categoryName in activeItems:
            activeItems.remove(categoryName)
        activeItems.extend(f"{categoryName} - {sub}" for sub in subcategories if f"{categoryName} - {sub}" not in activeItems)
        # Disable main category buttons and grey out the text
        for buttonGroups in buttonGroupsList:
            for button in buttonGroups[categoryName.strip()].buttons():
                button.setDisabled(True)
        label.setStyleSheet("QLabel { color: grey; }")  # Grey out the parent label text
    else:
        activeItems.append(categoryName)
        for sub in subcategories:
            subItem = f"{categoryName} - {sub}"
            if subItem in activeItems:
                activeItems.remove(subItem)
        # Enable main category buttons and ungrey the text
        for buttonGroups in buttonGroupsList:
            for button in buttonGroups[categoryName.strip()].buttons():
                button.setDisabled(False)
        label.setStyleSheet("QLabel { color: black; }")  # Reset the label text color
    ReorderActiveItems(activeItems, categoryList)

def SubcatLayout(subcategory, severityList, buttonGroupsList, parentCategory):
    subcategoryLayout = QHBoxLayout()

    # Frame for dropdown button and subcategory labels
    frameLabels = QFrame()
    layoutLabels = QVBoxLayout()
    layoutLabels.setSpacing(0)
    layoutLabels.setContentsMargins(20, 0, 0, 0)
    frameLabels.setLayout(layoutLabels)

    frames = []
    layouts = []

    for _ in buttonGroupsList:
        frame = QFrame()
        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(10, 0, 0, 1)
        frame.setLayout(layout)
        frames.append(frame)
        layouts.append(layout)

    subcategoryLabel = QLabel(subcategory)
    subcategoryLabel.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    layoutLabels.addWidget(subcategoryLabel)

    for layout, buttonGroups in zip(layouts, buttonGroupsList):
        buttonGroup, subcategoryButtonLayout = ButtonGroup(severityList)
        layout.addLayout(subcategoryButtonLayout)
        buttonGroups[f"{parentCategory} - {subcategory}"] = buttonGroup

    subcategoryLayout.addWidget(frameLabels)
    for frame in frames:
        subcategoryLayout.addWidget(frame)

    return subcategoryLayout

def ReorderActiveItems(activeItems, categoryList):
    orderedActiveItems = []
    for categoryName, subcategories in categoryList:
        if categoryName in activeItems:
            orderedActiveItems.append(categoryName)
        for subcategory in subcategories:
            subItem = f"{categoryName} - {subcategory}"
            if subItem in activeItems:
                orderedActiveItems.append(subItem)
    activeItems[:] = orderedActiveItems

def DisplayResults(buttonGroupsList, activeItems):
    returnValue = []
    totalSeverityValue = 0
    numCategories = 0
    
    for idx, buttonGroups in enumerate(buttonGroupsList):
        for item in activeItems or buttonGroups.keys():
            if item in buttonGroups:
                buttonGroup = buttonGroups[item]
                selectedButton = buttonGroup.checkedButton()
                if selectedButton:
                    severityLabel = selectedButton.text()
                    severityValue = selectedButton.property('severity_value')
                    returnValue.append([idx + 1, item, severityLabel, severityValue])  # Added group index (1-based)
                    totalSeverityValue += severityValue
                    numCategories += 1
    
    return returnValue

def CreateLayout(mainLayout, severityList, categoryList, numButtonGroups):
    buttonGroupsList = [{} for _ in range(numButtonGroups)]  # Create a list of empty dictionaries for button groups
    activeItems = CatLayout(mainLayout, buttonGroupsList, categoryList, severityList)
    return buttonGroupsList, activeItems

def MapDataCategories(returnValue):
    severityMap = {"Low": 0, "Medium": 1, "High": 2}

    if len(returnValue) < 2:
        return "Incomplete data"

    # Automatically assign the first and second categories
    dataRateLevel = returnValue[0][2]
    publishersLevel = returnValue[1][2]

    dataRateIndex = severityMap.get(dataRateLevel)
    publishersIndex = severityMap.get(publishersLevel)

    if dataRateIndex is None or publishersIndex is None:
        return "Invalid severity level"

    chart = [
        [["Very Low", 0.1], ["Low", 0.3], ["Moderate", 0.75]],
        [["Low", 0.3], ["Moderate", 0.75], ["High", 0.9]],
        [["Moderate", 0.75], ["High", 0.9], ["Very High", 1.0]]
    ]

    result = chart[publishersIndex][dataRateIndex]

    return result

