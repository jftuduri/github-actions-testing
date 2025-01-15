import json

class Validator:
    """
    Class in charge of validating that the CPE platforms, if any, are only OS-related.
    """

    def validate(self, content : json):
        return self.validatePlatforms(self, content)

    def validatePlatforms(self, content : json):
        affected_list = content.get("data", {}).get("containers", {}).get("cna", {}).get("affected", [])
        for affected in affected_list:
            if "platforms" not in affected:
                continue
            for platform in affected['platforms']:
                if platform.startswith("cpe:"):
                    if self.getCpePart(platform) != 'o':
                        raise ValueError("Only OS-related platforms are allowed.")

    def getCpePart(cpe):
        # The following CPE structures are expected:
        # - cpe:<part>:
        # - cpe:/<part>:
        # - cpe:2.3:<part>:
        # - cpe:2.3:/<part>:
        partIndex = 8 if cpe.startswith("cpe:2.3:") else 4
        if cpe[partIndex] == '/':
            partIndex += 1
        return cpe[partIndex]
