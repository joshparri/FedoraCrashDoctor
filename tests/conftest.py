import os

# Tests must never open visible Fedora Crash Doctor windows.
# This prevents disruptive popup windows during automated testing.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
