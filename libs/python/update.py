import json
import os
import requests
import config
import sys

path_root = os.getcwd()
path_ver_code = os.path.join(path_root, "VerCode.json")

def get_version():
    """
    Fetch the latest version information from the provided URL.
    
    Returns:
        str: The latest version as a string.
    """
    try:
        res = requests.get(config.url_version)
        res.raise_for_status()
        return res.content.decode('utf8')
    except requests.RequestException as e:
        print(f'[Error] Failed to fetch version information: {e}', file=sys.stderr)
        return None

def check_update():
    """
    Check if an update is needed by comparing local version information
    with the latest version available online.
    
    Returns:
        bool: True if an update is needed, False otherwise.
    """
    if os.path.exists(path_ver_code):
        try:
            with open(path_ver_code) as f_ver_code:
                data_ver_code = json.load(f_ver_code)
                version_ver_code = data_ver_code.get("appVer")
                version_atlas = get_version()
                
                if version_atlas is None:
                    print('[Error] Could not retrieve the latest version.', file=sys.stderr)
                    return False

                if version_ver_code != version_atlas:
                    print("[Update] An update is needed.", file=sys.stdout)
                    return True
                else:
                    print('[Update] No update is necessary.', file=sys.stdout)
                    return False
        except (json.JSONDecodeError, KeyError) as e:
            print(f'[Error] Error reading version file: {e}', file=sys.stderr)
            return False
    else:
        print('[Info] First-time setup detected. An update is required.', file=sys.stdout)
        return True

if __name__ == "__main__":
    update_needed = check_update()
    print(f'Update needed: {update_needed}', file=sys.stdout)
