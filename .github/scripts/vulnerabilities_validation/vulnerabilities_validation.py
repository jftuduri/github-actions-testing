import sys
import json
from importlib import import_module
import os
from os import listdir
from os.path import isfile, join
from pathlib import Path
import traceback

def read_json_file(file_path):
    """
    Reads a JSON file and returns the parsed data.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        dict: Parsed JSON data.
    """
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

if len(sys.argv) < 2:
    print("Usage: " + sys.argv[0] + " <action_files_list>")
    exit(1)

# Folder where the validation scripts reside.
modules_folder = os.path.dirname(os.path.realpath(__file__)) + "/modules/"
sys.path.insert(0, modules_folder)

# Load modules.
modules = []
for module_file in [f for f in listdir(modules_folder) if isfile(join(modules_folder, f))]:
    new_module = import_module(Path(module_file).stem)
    modules.append(getattr(new_module, 'Validator'))

# Initialize modules, if needed.
for module in modules:
    if hasattr(module, 'initialize'):
        module.initialize(module)

# Set input action files to validate.
action_files = []
for arg in sys.argv[1:]:
    action_files.extend(arg.split())

# Validate each action file.
success = True
for action_file in action_files:
    try:
        content = read_json_file(action_file)
    except Exception as error:
        success = False
        print("Error reading file '" + action_file + "': ")
        print(traceback.format_exc())
        continue

    for module in modules:
        try:
            module.validate(module, content)
        except ValueError as error:
            success = False
            print("Error validating file '" + action_file + "': " + str(error))
        except Exception as error:
            success = False
            print("Error validating file '" + action_file + "': ")
            print(traceback.format_exc())

# Exit.
exit(0 if success else 1)
