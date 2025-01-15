import json
import re

class Validator:
    """
    Class in charge of validating that there are not hardware-related CPEs within a CVE entry.
    """

    def validate(self, content : json):
        return self.validateHardwareCpes(self, content)

    def validateHardwareCpes(self, content : json):
        affected_list = content.get("data", {}).get("containers", {}).get("cna", {}).get("affected", [])
        for affected in affected_list:
            if "cpes" not in affected:
                continue
            for cpe in affected['cpes']:
                if self.getCpePart(cpe) == 'h':
                    raise ValueError("Hardware CPEs are not allowed.")

    def getCpePart(cpe):
        splited_cpe = re.split(r'(?<!\\):', cpe)
        splited_cpe = [part.replace(r'\:', ':') for part in splited_cpe]
        return splited_cpe[2]
