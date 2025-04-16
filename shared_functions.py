"""
Module for functions that are (or were) used multiple times across the project.
"""
from PySide6.QtWidgets import QPushButton, QSizePolicy

low = "#90EE90"  # Low
medium = "#ffd68b"  # Medium
high = "#f09d9d"  # High
critical = "#e47676"  # High

def interpolate_colour(startColour, endColour, factor):
    """
    Interpolates between two hex color values based on a given factor.
    """
    startColour = startColour.lstrip('#')
    endColour = endColour.lstrip('#')
    sr, sg, sb = int(startColour[0:2], 16), int(startColour[2:4], 16), int(startColour[4:6], 16)
    er, eg, eb = int(endColour[0:2], 16), int(endColour[2:4], 16), int(endColour[4:6], 16)
    
    r = int(sr + (er - sr) * factor)
    g = int(sg + (eg - sg) * factor)
    b = int(sb + (eb - sb) * factor)
    
    return f'#{r:02x}{g:02x}{b:02x}'

def create_result_button(defaultColor):
    """
    Creates a styled QPushButton for displaying severity results.
    """
    resultButton = QPushButton("")
    resultButton.setEnabled(False)
    resultButton.setStyleSheet(f"border-radius: 3px; color: black; background-color: {defaultColor};")
    resultButton.setFixedHeight(20)
    resultButton.setFixedWidth(230)
    resultButton.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
    resultButton.setToolTip("This button shows the calculated severity value.")

    return resultButton

def update_result_button(resultButton, value, placeholder):
    """
    Updates the text and background color of a result button based on a numeric value.
    """
    colors = [(0, "#bababa"), (0.3, low), (0.6, medium), (1, high)]
    
    for i in range(len(colors) - 1):
        if colors[i][0] <= value <= colors[i + 1][0]:
            factor = (value - colors[i][0]) / (colors[i + 1][0] - colors[i][0])
            color = interpolate_colour(colors[i][1], colors[i + 1][1], factor)
            break
    else:
        color = colors[-1][1]

    value = min(value, 1)

    resultButton.setText(f"{placeholder}: {value:.2f}")
    resultButton.setStyleSheet(f"background-color: {color}; border-radius: 3px; color: black;")