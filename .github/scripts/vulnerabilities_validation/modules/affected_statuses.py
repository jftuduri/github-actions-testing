import json

class Validator:
    """
    Class in charge of validating the affected statuses within a CVE entry.
    """

    def validate(self, content : json):
        return self.validateAffectedStatuses(content)

    def validateAffectedStatuses(content : json):
        affected_list = content.get("data", {}).get("containers", {}).get("cna", {}).get("affected", [])
        for affected in affected_list:
            default_status = affected.get("defaultStatus")
            versions = affected.get("versions", [])

            for version in versions:
                if version["status"] == default_status:
                    raise ValueError("The 'versions[].status' should be different from 'affected[].defaultStatus'.")
