import json

class Validator:
    """
    Class in charge of validating that there are not wildcard (*) versions within a CVE entry.
    """

    def validate(self, content : json):
        return self.validateWildcardVersions(content)

    def validateWildcardVersions(content : json):
        version_keys = ["version", "lessThan", "lessThanOrEqual"]
        affected_list = content.get("data", {}).get("containers", {}).get("cna", {}).get("affected", [])
        for affected in affected_list:
            versions = affected.get("versions", [])
            for versionObject in versions:
                for key in version_keys:
                    if key in versionObject and versionObject.get(key) == "*":
                        raise ValueError("Wildcard versions (*) are not allowed.")
