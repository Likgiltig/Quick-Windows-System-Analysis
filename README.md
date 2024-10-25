### **Quick Windows System Analysis**

**A Python project that does a small scan of hardware components and event logs on Windows systems, this generates a report that can be used when checking a computer for Issues / Errors.**

**Prerequisites:**
* pywin32
* WMI


**Installation:**
1. Clone this repository:
   ```bash
   git clone https://github.com/Likgiltig/Quick-WIndows-System-Analysis.git
   ```
2. Install the required dependencies:
   ```bash
   pip install pywin32, WMI
   ```
   
**Basic Usage:**
   ```bash
    python win_sys_analysis.py
   ```

**This will do the following:**
1. Collect hardware information.
2. Collect event logs from the past 7 days.
3. Generating report with that collected information.
4. Save the report to the folder named 'system_analysis'.
5. Save error eventlogs as a json file to that same folder.


**Recommendation:**

To be able to run this script you need to run it using a privilaged terminal.

Using a virtual environment is highly recommended to isolate project dependencies and avoid conflicts with other Python projects. This ensures a cleaner and more predictable development environment.
