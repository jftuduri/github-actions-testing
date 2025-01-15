# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import json
import subprocess
import os
import time
from pathlib import Path
import logging
import pytest
import requests_unixsocket
import shutil
from dataclasses import dataclass
from typing import List
from helpers import set_command, clean_env, logs_folder, passed_test_logs_folder, failed_test_logs_folder
from enum import Enum

LOGGER = logging.getLogger(__name__)
SOCKET_PATH = "test.sock"
VD_ENDPOINT = "/vulnerability/scan"


class TestResult:
    status: bool
    errors: list[str]

    def __init__(self, status: bool, errors: list[str]):
        self.status = status
        self.errors = errors

    def __str__(self):
        return f"status: {self.status}, errors: {self.errors}"

    def __repr__(self):
        return f"status: {self.status}, errors: {self.errors}"


class TestOutcome(Enum):
    PASSED = "Passed"
    FAILED = "Failed"


@dataclass
class ResponsePair:
    expected: dict
    actual: dict


class TestData:
    response_pairs: List[ResponsePair]

    def __init__(self, expected_response: dict, actual_response: dict):
        # Relate the expected and actual responses by the id and item_id fields.
        self.response_pairs = [
            ResponsePair(x, y)
            for x in expected_response
            for y in actual_response
            if (x.get("item_id") is None and x.get("id") == y.get("id")) or
           (x.get("id") == y.get("id") and x.get("item_id") == y.get("item_id"))
        ]

    def validate_responses(self) -> List[TestResult]:
        results = []
        for response_pair in self.response_pairs:
            results.append(self.__validate_response(response_pair))

        return results

    @staticmethod
    def __format_error(expected_response: dict, key: str, actual_response: dict) -> str:
        """
        Format the error message when the expected value is different from the actual value.
        """
        return f'{expected_response["id"]}: "{key}" expects "{expected_response[key]}" but got "{actual_response[key]}".'

    @staticmethod
    def __format_error(expected_response: dict, key: str) -> str:
        """
        Format the error message when the key is not found in the response.
        """
        return f'{expected_response["id"]}: "{key}" not found in the response.'

    @staticmethod
    def __validate_response(response_pair: ResponsePair) -> TestResult:
        errors = []

        expected_response = response_pair.expected
        actual_response = response_pair.actual

        for key in expected_response.keys():
            # Validate the key exists in the actual response
            if key not in actual_response:
                errors.append(TestData.__format_error(expected_response, key))
            else:
                # Score contains an object
                if key == "score":
                    for score_key in expected_response[key].keys():
                        if score_key not in actual_response[key]:
                            errors.append(
                                TestData.__format_error(
                                    expected_response, f"{key}.{score_key}"
                                )
                            )
                        elif (
                            expected_response[key][score_key]
                            != actual_response[key][score_key]
                        ):
                            errors.append(
                                TestData.__format_error(
                                    expected_response,
                                    f"{key}.{score_key}",
                                    actual_response,
                                )
                            )
                else:
                    if expected_response[key] != actual_response[key]:
                        errors.append(
                            TestData.__format_error(
                                expected_response, key, actual_response
                            )
                        )

        if not errors:
            return TestResult(status=True, errors=[])

        return TestResult(status=False, errors=errors)


class MissingKeyException(Exception):
    """
    Exception raised when a required key is missing from an item.
    """

    def __init__(self, key):
        self.key = key
        super().__init__(f"Missing key: {key}")


@pytest.fixture(scope="session", autouse=True)
def setup_folder():
    # Delete the folder if exists
    if Path(logs_folder).exists():
        shutil.rmtree(logs_folder)

    # Create folder
    Path(logs_folder).mkdir()
    Path(passed_test_logs_folder).mkdir()
    Path(failed_test_logs_folder).mkdir()


def send_http_request_unixsocket(data):
    """
    Sends a http data to a Unix socket.

    Args:
        data (bytes): The http data to be sent.

    Returns:
        None: If the socket does not exist or an error occurs during the socket connection or data sending.
    """

    # Connect to http server using Unix socket
    # Use requests to send data to the socket
    url = f"http+unix://{SOCKET_PATH.replace('/', '%2F')}{VD_ENDPOINT}"
    # Send the data
    response = requests_unixsocket.post(url, json=data)
    assert (
        response.status_code == 200
    ), f"Error sending data to the socket: {response.status_code}"

    # Parses the response and checks if it is null. If it is, return None.
    json_response = response.json()
    if json_response is None:
        return None

    return sorted(json_response, key=lambda x: x["id"])


def execute_test(test_folder: str, validate_expected: bool = True) -> List[TestResult]:
    """
    1. Sends the input file to the socket.
    2. Compares the response with the expected response.
    3. Repeat for each pair of files in the test folder.
    4. Returns the test results.

    Args:
        test_folder (str): The path to the test folder.
        validate_expected (bool): If True, the expected data will be validated (default: True).

    Returns:
        None
    """

    input_files = sorted(Path(test_folder).glob("input_*.json"))
    expected_files = sorted(Path(test_folder).glob("expected_*.json"))
    assert len(input_files) == len(
        expected_files
    ), "Input and expected files number mismatch"

    tests_results: List[TestResult] = []

    # For each pair of files, send the input file to the socket and compare the response with the expected one
    for input_file_path, expected_file_path in zip(input_files, expected_files):
        LOGGER.debug(f"Running test for '{input_file_path}'")

        expected_data = json.load(open(expected_file_path))
        expected_data.sort(key=lambda x: x["id"])

        # Validate the expected data
        if validate_expected:
            for item in expected_data:
                if "category" not in item:
                    raise MissingKeyException("category")
                if "condition" not in item:
                    raise MissingKeyException("condition")
                if "source" not in item:
                    raise MissingKeyException("source")

                # OS packages do not have item_id
                if item["category"] != "OS":
                    if "item_id" not in item:
                        raise MissingKeyException("item_id")

        input_data = json.load(open(input_file_path))
        response_data = send_http_request_unixsocket(input_data)

        test_data = None
        # response_data is None when there are no vulnerabilities for the given input data.
        if response_data is not None:
            test_data = TestData(expected_data, response_data)

        #  For false negative tests, we expect to find all the vulnerabilities in the expected response
        if test_folder.parent.name == "test_false_negative_data":
            assert len(test_data.response_pairs) == len(
                expected_data
            ), "One or more expected vulnerabilities were not detected."

        # test_data is None when there are no vulnerabilities for the given input data. In this case, we
        # do not need to validate the response.
        if test_data is not None:
            for result in test_data.validate_responses():
                tests_results.append(result)

    return tests_results


def move_logs(result: TestOutcome, log_path):
    """
    Move logs to the corresponding folder.

    Args:
        result: The test outcome.
        log_path: The path to the log file.

    Returns:
        None
    """
    if result == TestOutcome.PASSED:
        shutil.move(log_path, passed_test_logs_folder)
    elif result == TestOutcome.FAILED:
        shutil.move(log_path, failed_test_logs_folder)
        

@pytest.fixture
def run_process_and_monitor_response(request):
    """
    Runs the vulnerability scanner test tool and monitors the API response for expected lines.

    Args:
        request: The request object containing the test parameters.
    Returns:
        A dictionary containing the found lines and their status.

    Raises:
        AssertionError: If the binary does not exist.
        AssertionError: If the process is not initialized.
        AssertionError: If the scan is not finished or some events were not processed.
    """
    test_folder = request.param

    filename = test_folder.parent.name + "_" + test_folder.name + ".log"

    clean_env(filename)
    command, log_path = set_command(filename)
    LOGGER.debug(f"Running test {test_folder}")

    if Path(SOCKET_PATH).exists():
        os.remove(SOCKET_PATH)

    with subprocess.Popen(command) as process:
        start_time = time.time()
        # Check socket file exists
        while not Path(SOCKET_PATH).exists() and (time.time() - start_time <= 10):
            time.sleep(1)
        assert Path(SOCKET_PATH).exists(), "The socket file does not exists."

        # Waiting for vulnerability scanner HTTP server.
        start_time = time.time()
        while not Path(log_path).exists() and (time.time() - start_time <= 10):
            time.sleep(1)
        assert Path(log_path).exists(), "The log file does not exists."

        # Iterate over json files in the test directory, and send through unix socket.
        try:
            test_result = []
            if test_folder.parent.name == "test_false_positive_data":
                # We do not validate the expected data for false positive tests
                test_result = execute_test(test_folder, validate_expected=False)
            elif test_folder.parent.name == "test_false_negative_data":
                test_result = execute_test(test_folder)

            process.terminate()
            move_logs(TestOutcome.PASSED, log_path)

            return test_result

        except MissingKeyException as e:
            process.terminate()
            move_logs(TestOutcome.FAILED, log_path)
            LOGGER.error(f"{e}")
            return None

        except Exception as e:
            process.terminate()
            move_logs(TestOutcome.FAILED, log_path)
            if test_folder.parent.name == "test_false_positive_data":
                return []
            else:
                LOGGER.error(f"{e}")
                return None

    return None


test_false_negative_folders = sorted(
    Path(".github/vdscanner_efficacy_test/test_false_negative_data").glob(
        os.getenv("WAZUH_VD_TEST_FN_GLOB", "*")
    )
)
test_false_positive_folders = sorted(
    Path(".github/vdscanner_efficacy_test/test_false_positive_data").glob(
        os.getenv("WAZUH_VD_TEST_FP_GLOB", "*")
    )
)

# If only variable WAZUH_VD_TEST_X_GLOB is set, we only run the X tests.
if os.getenv("WAZUH_VD_TEST_FN_GLOB") and not os.getenv("WAZUH_VD_TEST_FP_GLOB"):
    test_false_positive_folders = []
elif os.getenv("WAZUH_VD_TEST_FP_GLOB") and not os.getenv("WAZUH_VD_TEST_FN_GLOB"):
    test_false_negative_folders = []


@pytest.mark.parametrize(
    "run_process_and_monitor_response", test_false_negative_folders, indirect=True
)
def test_false_negatives(run_process_and_monitor_response):
    """
    Test function to verify the accuracy of the vulnerability scanner module.

    Args:
        run_process_and_monitor_response: Fixture that runs the vulnerability scanner test tool and monitors the API response, comparing it with the expected response.

    Raises:
        AssertionError: If the expected vulnerability were not found in the API response.

    Returns:
        None
    """
    LOGGER.info("Running false negative test")

    test_results = run_process_and_monitor_response

    assert test_results != None, "No vulnerabilities found in the API response."

    for result in test_results:
        assert result.status, LOGGER.error(result.errors)


@pytest.mark.parametrize(
    "run_process_and_monitor_response", test_false_positive_folders, indirect=True
)
def test_false_positives(run_process_and_monitor_response):
    """
    Test function to verify the accuracy of the vulnerability scanner module.

    Args:
        run_process_and_monitor_response: Fixture that runs the vulnerability scanner test tool and monitors the API response, comparing it with the expected response.

    Raises:
        AssertionError: If an unexpected vulnerability was found in the API response.

    Returns:
        None
    """
    LOGGER.info("Running false positive test")

    test_results = run_process_and_monitor_response

    assert (
        len(test_results) == 0
    ), "The test failed because some unexpected vulnerability were found."
