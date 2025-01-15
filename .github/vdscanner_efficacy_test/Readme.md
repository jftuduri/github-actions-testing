# QA Tests

This document is meant to describe the current efficacy tests behavior and the steps required for its maintenance.

## Efficacy test

### Description

The purpose of these tests is to verify the scanner's accuracy when some specific inputs are applied. The results are verified by analyzing the scanner response against an expected response.

The enumerated folders in `test_x_data` are read in ascending order, and for each one of them, the corresponding inputs are sent. There is an expected output file that contains the information that the scanner should respond to those specific inputs.

For false negative cases, the test will fail if the expected information isn't found in the scanner response. For false positive cases, the opposite.

### How to add cases

When a new test is being added, these are the general steps to follow:
- Create a new folder, use the next available number.
- Add `input_xxx.json` files that contain the OS and/or package information that the vulnerability scanner test tool will process.
- For each input, create an `expected_xxx.json` file. The JSON objects in the array will be looked for in the test output.
For false negative cases the fields that will be evaluated are: category, condition, id, and item_id only in case the category is "Packages".
Optionally the fields description, score.base, score.version and severity can be added if the requirements demands it.

## Running local tests

To run the tests locally:
- Download the 4.10.0 compressed database and decompressed the queue folder content in `/var/lib/wazuh-server/`.
- Get the latest vulnerability scanner tools artifacts [vdscanner_tools](https://github.com/wazuh/wazuh/actions/workflows/engine_vdscanner_tools_delivery.yml)
- Update, if required, the base rules and translation information with the rocksdb tool.
- Run the tests with `python3 -m pytest -v .github/vdscanner_efficacy_test/test_efficacy_vdscanner.py`.
- Additionally we can add `--log-cli-level=DEBUG` for verbose output.
- A single test can be run with the environment variables `WAZUH_VD_TEST_FN_GLOB`, or `WAZUH_VD_TEST_FP_GLOB`.

Examples:

- `WAZUH_VD_TEST_FN_GLOB=001 python3 -m pytest -v .github/vdscanner_efficacy_test/test_efficacy_vdscanner.py --log-cli-level=DEBUG`
- `WAZUH_VD_TEST_FP_GLOB=001 python3 -m pytest -v .github/vdscanner_efficacy_test/test_efficacy_vdscanner.py --log-cli-level=DEBUG`
- `python3 -m pytest -rA --html=report.html --self-contained-html -vv engine/source/vdscanner/qa/ --log-cli-level=DEBUG`
