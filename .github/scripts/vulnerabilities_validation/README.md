# Vulnerabilities sanitization validation

The [vulnerabilities_validation](./vulnerabilities_validation.py) script validates that the sanitizations performed over the vulnerability content are compliant with what the Vulnerability Scanner is expecting, making various assertions within each CVE document in this repository.

In order to perform different validations, the script uses different [module scripts](./modules/), each of which is destined to validate a specific characteristic of a document.

The current module scripts are:
- [Affected Statuses](#affected-statuses)
- [Hardware CPEs](#hardware-cpes)
- [Non OS-related platforms](#non-os-related-platforms)
- [Wildcard versions](#wildcard-versions)

## Modules

### Affected Statuses

The script [affected_statuses](./modules/affected_statuses.py) ensures that there are no `affected` entries where a `defaultStatus` is equal to any of the `status` within a `versions` object.

#### Example

An example of an uncompliant entry is below. Note that the version `status` and the `defaultStatus` are equal to `unaffected`.

```json
{
    "defaultStatus": "unaffected",
    "product": "aix",
    "vendor": "ibm",
    "versions": [
        {
            "status": "unaffected",
            "version": "4.1"
        }
    ]
}
```

### Hardware CPEs

The script [hardware_cpes](./modules/hardware_cpes.py) ensures that there are no `affected` entries with CPE vectors that refer to a hardware vulnerability. In these cases, the third part of a CPE is equal to `h`.

> Note: This check is only made within the `affected[].cpes` field, not in `affected[].platforms`.

#### Example

An example of an uncompliant entry is below.

```json
{
    "cpes": [
        "cpe:2.3:h:lenovo:thinkpad_10_ella_2:-:*:*:*:*:*:*:*"
    ],
    "defaultStatus": "affected",
    "platforms": [
        "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_7:*:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_8.1:*:*:*:*:*:*:*:*"
    ],
    "product": "thinkpad_10_ella_2",
    "vendor": "lenovo"
}
```

### Non OS-related platforms

The script [non_os_platforms](./modules/non_os_platforms.py) ensures that there are no `affected` entries with CPE vectors, used as platforms, that refer to a hardware or to an application. In these cases, the third part of the CPE is equal to `h` or `a`.

> Note: This check is only made within the `affected[].platforms` field, not in `affected[].cpes`.

#### Example

An example of an uncompliant entry is below.

```json
{
    "cpes": [
        "cpe:2.3:a:nortel:net_direct_client:*:*:linux:*:*:*:*:*"
    ],
    "defaultStatus": "unaffected",
    "platforms": [
        "cpe:2.3:h:nortel:alteon_2424_application_switch:23.2:*:*:*:*:*:*:*",
        "cpe:2.3:h:nortel:ssl_vpn_module_1000:*:*:*:*:*:*:*:*",
        "cpe:2.3:h:nortel:vpn_gateway_3070:*:*:*:*:*:*:*:*"
    ],
    "product": "net_direct_client linux",
    "vendor": "nortel",
    "versions": [
        {
            "lessThanOrEqual": "6.0.4",
            "status": "affected",
            "version": "0",
            "versionType": "custom"
        }
    ]
}
```

### Wildcard versions

The script [wildcard_versions](./modules/wildcard_versions.py) ensures that there are no `affected` entries with versions equal to `*`.

> Note: The fields analyzed are `versions[].version`, `versions[].lessThan`, and `versions[].lessThanOrEqual`.

#### Example

An example of an uncompliant entry is below.

```json
{
    "cpes": [
        "cpe:2.3:a:sun:j2ee:*:*:*:*:*:*:*:*"
    ],
    "defaultStatus": "unaffected",
    "product": "j2ee",
    "vendor": "sun",
    "versions": [
        {
            "status": "affected",
            "version": "0",
            "lessThanOrEqual": "*",
            "versionType": "custom"
        }
    ]
}
```

## Adding a new module

In order to add a new module to be executed by the main script, it is necessary to add a new Python script file in the [modules folder](./modules/). This script must contain:
- A definition of a class called *Validator*.
- A class method called *validate*, that performs the necessary checks and raises a `ValueError` exception when the validation is not successful.
- Optionally, the class can hold a method called *initialize* that will be executed once before starting with the validations. This is useful if, for example, the validator needs input data that won't change between validations.

For example, a very simple validator that checks that the basic fields exist could be:

```python
import json

class Validator:

    def initialize(self):
        print("Validator initialized!")

    def validate(self, content : json):
        if not 'data' in content or not 'operation' in content:
            raise ValueError("The 'operation' and 'data' fields should exist.")
```

## Execution

The script has just one argument: The list of files to validate.

These are some examples of how the script can be executed (from the root folder of this repository):

- Validate just one file
```bash
% python .github/scripts/vulnerabilities_validation/vulnerabilities_validation.py vulnerabilities/CVE-2024-25817/CANONICAL/action.json
```

- Validate multiple files
```bash
% python .github/scripts/vulnerabilities_validation/vulnerabilities_validation.py vulnerabilities/CVE-2024-25817/CANONICAL/action.json vulnerabilities/CVE-2022-24329/DEBIAN/action.json
```

- Validate all vulnerability files within the repository
```bash
% python .github/scripts/vulnerabilities_validation/vulnerabilities_validation.py $(find vulnerabilities -name "action.json" | tr '\n' ' ')
```
