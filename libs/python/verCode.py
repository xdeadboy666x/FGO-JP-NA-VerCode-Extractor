import json
import os
import re
import config
import sys

from libs.python.update import get_version

# List of known non-verCode values
is_not_ver_code = [
    "5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72",
    "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    "7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee",
    "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
]

def write_verCode_data():
    """
    Write the version code data to a JSON file if certain conditions are met.
    """
    try:
        string_literal_path = os.path.join(config.temp_folder, "decrypt", "stringliteral.json")
        with open(string_literal_path, encoding="utf8") as string_literal_file:
            json_data = json.load(string_literal_file)

        print("[App] Writing verCode data...", file=sys.stdout)

        for data in json_data:
            value = data['value']

            if len(value) == 64:
                is_hash = len(re.findall("^[a-fA-F0-9]{64}$", value)) > 0

                if is_hash and value.islower() and value not in is_not_ver_code:
                    # Create JSON
                    version_latest = get_version()
                    
                    if version_latest is None:
                        print('[Error] Could not retrieve the latest version.', file=sys.stderr)
                        return
                    
                    data_ver_code = {
                        "appVer": version_latest,
                        "verCode": value
                    }

                    ver_code_path = os.path.join(os.getcwd(), "VerCode.json")
                    with open(ver_code_path, "w") as file:
                        json.dump(data_ver_code, file)

                    print("[App] VerCode exported successfully!", file=sys.stdout)
                    return

        print("[App] No valid verCode found.", file=sys.stdout)

    except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
        print(f'[Error] An error occurred while processing the verCode data: {e}', file=sys.stderr)
    except Exception as e:
        print(f'[Error] An unexpected error occurred: {e}', file=sys.stderr)

if __name__ == "__main__":
    write_verCode_data()
