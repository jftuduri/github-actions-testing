import json
import os 

GENERAL_CONSTRAINTS_FILE='../../../actions/schemas/general_constraints.json'

class Validator:
    """
    Class in charge of validating that the x_subShortName field has an allowed value.
    In its initialization, it reads the GENERAL_CONSTRAINTS_FILE file in order to load the x_subShortName allowed values.
    """

    def initialize(self):
        current_file_folder = os.path.dirname(os.path.realpath(__file__))
        constraints = json.load(open(current_file_folder + "/" + GENERAL_CONSTRAINTS_FILE))
        self.allowedValues = []
        for value in constraints['vulnerabilities']['providers']['allowedValues']:
            self.allowedValues.append(value.lower())

    def validate(self, content : json):
        return self.validateXSubShortName(self, content)

    def validateXSubShortName(self, content : json):
        x_sub_short_name = content.get("data", {}).get("containers", {}).get("cna", {}).get("providerMetadata", []).get("x_subShortName", [])
        if x_sub_short_name not in self.allowedValues:
            raise ValueError("Not allowed x_subShortName: " + x_sub_short_name)
