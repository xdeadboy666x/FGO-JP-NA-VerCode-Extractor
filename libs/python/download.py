import os
import sys
import requests
import config

def download_latest():
    """
    Download the latest APK file from the specified URL and save it to the temp folder.
    """
    try:
        print('[App] Creating folders...', file=sys.stdout)
        os.makedirs(os.path.join(config.temp_folder, "decrypt"), exist_ok=True)

        print('[App] Downloading latest APK...', file=sys.stdout)
        apk_path = os.path.join(config.temp_folder, "fate.apk")

        # Download and save the APK file
        response = requests.get(config.url_apk)
        response.raise_for_status()  # Raise an error for bad status codes

        with open(apk_path, "wb") as apk_file:
            apk_file.write(response.content)

        print('[App] APK downloaded successfully!', file=sys.stdout)
    except requests.RequestException as e:
        print(f'[Error] Failed to download APK: {e}', file=sys.stderr)
    except OSError as e:
        print(f'[Error] Failed to create folders or save APK: {e}', file=sys.stderr)
    except Exception as e:
        print(f'[Error] An unexpected error occurred: {e}', file=sys.stderr)

if __name__ == "__main__":
    download_latest()
