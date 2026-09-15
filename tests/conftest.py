# Standard library imports
import os

# `aeth_ext` builds its settings at import time and requires the alert password; in the
# container the compose file sets it, here a placeholder does (the tests ping nothing).
os.environ.setdefault("ALERTS_EMAIL_PWD", "test-placeholder")
