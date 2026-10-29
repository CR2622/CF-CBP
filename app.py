"""
CyberTrace Root Launcher
Enables direct invocation from project workspace:
    streamlit run app.py
"""

import os
import sys

# Ensure cybertrace directory is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CYBERTRACE_DIR = os.path.join(BASE_DIR, "cybertrace")
if CYBERTRACE_DIR not in sys.path:
    sys.path.insert(0, CYBERTRACE_DIR)

# Change current working directory to cybertrace so relative paths resolve cleanly
os.chdir(CYBERTRACE_DIR)

# Execute cybertrace/app.py
with open(os.path.join(CYBERTRACE_DIR, "app.py"), "r", encoding="utf-8") as f:
    app_code = f.read()

exec(compile(app_code, os.path.join(CYBERTRACE_DIR, "app.py"), "exec"))
