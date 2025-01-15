# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from pathlib import Path

logs_folder = "test_logs"
passed_test_logs_folder = logs_folder + "/passed_test"
failed_test_logs_folder = logs_folder + "/failed_test"

def clean_env(filename):
    # Delete previous inventory directory if exists
    if Path("queue/vd/inventory").exists():
        for file in Path("queue/vd/inventory").glob("*"):
            file.unlink()
        Path("queue/vd/inventory").rmdir()

    log_path = os.path.join(logs_folder, filename)

    # Remove previous log file if exists
    if Path(log_path).exists():
        Path(log_path).unlink()


def set_command(filename):
    # Set the path to the binary
    cmd = Path("scanner/", "vdscanner_tool")
    assert cmd.exists(), "The binary does not exists"

    log_path = os.path.join(logs_folder, filename)

    args = ["-l", log_path,
            "-s", "test.sock"]

    return (([cmd] + args), log_path)
