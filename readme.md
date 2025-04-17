# ARC-C: Automated Risk-Based Cryptoperiod Calculation

ARC-C (Automated Risk-Based Cryptoperiod Calculator) is a tool designed to help determine optimal cryptoperiod durations in Industrial Control Systems (ICSs) exposed to data siphoning attacks. By factoring in both system-specific risk parameters and threat intelligence, ARC-C ensures that encryption key lifetimes are neither too short to be inefficient nor too long to be insecure - striking a balance to minimizing risk without compromising operational performance.

## Getting Started

If you only want to test out ARC-C without making modifications to the source code, you can simply run the executible, `ARC-C.exe`. 

Note that for efficient usage, an NVD API key is recommended. [Visit this website to request a key](https://nvd.nist.gov/developers/request-an-api-key). Once you receieve a key, follow the formatting in `.env.example` and create an `.env` file in the same directory as the exe.

#### Installation 
1. Clone the repo `https://github.com/itzagabe/ARC_C`
2. Install the requirements via `pip install -r requirements.txt`
3. Run `main.py`

## Using The UI

ARC-C can be broken down into 5 sections:  
- Probability of Software Compromise (P<sub>VE-software-succ</sub>)
- Upper and Lower bounds (T<sub>CP-max</sub> and T<sub>CP-min</sub>)
- Procedural Policy (P<sub>VE-procedure-succ</sub>)
- Information Rate (IR<sub>SG</sub>)
- Functional Importance (FI<sub>SG</sub>)

![ARC-C Labelled UI](https://github.com/user-attachments/assets/63fb3ee8-0772-4d0e-8d23-75d93096b28d)

##### Probability of Software Compromise (P<sub>VE-software-succ</sub>)

The most involved calculation occurs in the software compromise panel. Here, there are three options which can be used to import devices:  
- Individual: type a devices official Common Platform Enumeration (CPE)
- Group: import a `.txt` file with a CPE on each unique line (lines starting with `#` will be ignored)
- Manual: manually create a CPE, including associated Common Vulnerablities and Exposures (CVEs)

By default, ARC-C will select what it deems the most appropriate result associated with a given search term. However, this may not always return the correct result. For more control, `Detailed Search` can be selected. In this instance, all device CPEs associated with a given search term will be displayed and the correct version can be manually chosen.

Once a device is imported, it will be displayed in the aptly named "Imported Devices" list. Double click an entry to be taken to a window containing each individual CVE assocaited with that device. Checking/unchecking CVEs will add/remove them from the overall calculation, simulating a device being "patched".

##### Upper and Lower bounds (T<sub>CP-max</sub> and T<sub>CP-min</sub>)

Next are the bounds. Generally, the default T<sub>CP-min</sub> = 1 day and T<sub>CP-max</sub> = 1 year is sufficient, but these values can change relative to the needs of the environment.

##### Procedural Policy (P<sub>VE-procedure-succ</sub>), Information Rate (IR<sub>SG</sub>) and Functional Importance (FI<sub>SG</sub>)

The remaining three variables are set via radio buttons. These are represented by qualitative severity values which are determined by the operator.

After all values are set, "Calculate Cryptoperiod" will return the optimal cryptoperiod based on the assocaited values.

---

For a more in-depth explanation of how each variable operates, please refer to our paper ["Risk-Based Methodology for Optimal Cryptoperiod Calculation in ICSs Under Data Siphoning Attack"](https://dl.acm.org/doi/10.1145/3689930.3695203).  
A very in-depth overview of the qualitative parameter definitions can be found in Appendix C of my thesis, [ARC-C: Analytical Framework and Software Tool for Automated Risk-Based Cryptoperiod Calculation in Industrial Control Systems](https://yorkspace.library.yorku.ca/items/ffe62455-d55c-47df-a1f3-0816b86e9b9e)

## Making Changes

ARC-C was written in a way so that changes can be made fairly easily.

To change the overall formula:  
- `show_results()` in `main.py`

---

To change the software probability calculation:  
- `get_import_values()` and `calculate_resilience` in `import_devices_ui.py`
- `calculate_resilience` also contains the baseline resilience `b_d` and weight factor `c_w` which can be changed in the arguments

---

Modifying the radio buttons is a bit more complicated, as its implementation is a bit more involved. The logic follows a two step process:  
1. Defining the radio buttons themselves (severity score, categories, etc).
2. Defining the calculation applied to the radio buttons.

Defining the radio buttons is done by calling `create_generic_layout()` in `parameters_ui.py`.
- **severityList:** List of tuples specifying (label, score, color) for each 
      severity level.
- **categoryList:** List of category names or (name, subcategories) tuples 
      specifying the layout structure.
- **numButtonGroups:** Number of grouped buttons per category.
- **updateFunc:** Function to handle logic for computing and updating the result.
- **defaultColor:** Default background color for the result display.
- **tooltips:** Dictionary mapping label names to tooltip text.
- **createResultButton:** Boolean flag to indicate whether to add a result 
      display button to the layout.  
This is done for `impact_categories()`, `information_rate_categories()`, and `policy_categories()`.

Since each set of radio buttons manipulates the assigned values differently (i.e information rate maps the input to a set value while functional importance has an entirely unique formula), an update function must be written for each initialization.  
This is done in `update_impact_layout()`, `update_information_rate_layout()` and `update_policy_layout()`.  
_Note: that since policy strength does not require any extra calculations after the initial qualitative value is selected, the update function simply sets the current selected value._

## Acknowledgements

Natalija Vlajic, Thomas Nehring, Robert Noce, and Edgar Wolf, Marin Litoiu, Usman T Khan