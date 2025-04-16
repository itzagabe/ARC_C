from PySide6.QtWidgets import QPushButton, QSizePolicy

low = "#90EE90"  # Low
medium = "#ffd68b"  # Medium
high = "#f09d9d"  # High
critical = "#e47676"  # High

def InterpolateColour(startColour, endColour, factor):
    startColour = startColour.lstrip('#')
    endColour = endColour.lstrip('#')
    sr, sg, sb = int(startColour[0:2], 16), int(startColour[2:4], 16), int(startColour[4:6], 16)
    er, eg, eb = int(endColour[0:2], 16), int(endColour[2:4], 16), int(endColour[4:6], 16)
    
    r = int(sr + (er - sr) * factor)
    g = int(sg + (eg - sg) * factor)
    b = int(sb + (eb - sb) * factor)
    
    return f'#{r:02x}{g:02x}{b:02x}'

def CreateResultButtonWidget(defaultColor):
    resultButton = QPushButton("")
    resultButton.setEnabled(False)
    resultButton.setStyleSheet(f"border-radius: 3px; color: black; background-color: {defaultColor};")
    resultButton.setFixedHeight(20)
    resultButton.setFixedWidth(230)
    resultButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    resultButton.setToolTip("This button shows the calculated severity value.")

    return resultButton

def UpdateResultButton(resultButton, value, placeholder):
    colors = [(0, "#bababa"), (0.3, low), (0.6, medium), (1, high)]
    
    for i in range(len(colors) - 1):
        if colors[i][0] <= value <= colors[i + 1][0]:
            factor = (value - colors[i][0]) / (colors[i + 1][0] - colors[i][0])
            color = InterpolateColour(colors[i][1], colors[i + 1][1], factor)
            break
    else:
        color = colors[-1][1]

    value = min(value, 1)

    resultButton.setText(f"{placeholder}: {value:.2f}")
    resultButton.setStyleSheet(f"background-color: {color}; border-radius: 3px; color: black;")
    #resultButton.setAlignment(Qt.AlignCenter)  # Center the text