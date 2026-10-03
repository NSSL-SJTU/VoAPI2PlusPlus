import logging
from pathlib import Path
import os

def config_log(log_file: str, debug: bool = False, clean_log: bool = True):
    if clean_log:
        if os.path.exists(log_file):
            os.remove(log_file)
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    file_h = logging.FileHandler(log_file, encoding="utf-8")
    console_h = logging.StreamHandler()

    # Set log level based on debug flag
    log_level = logging.DEBUG if debug else logging.INFO

    file_h.setLevel(log_level)
    console_h.setLevel(log_level)
    file_h.setFormatter(fmt)
    console_h.setFormatter(fmt)
    logging.basicConfig(handlers=[file_h, console_h], level=log_level)
