import os
import requests

# URL for the APK file
url_apk = "https://fgo.square.ovh/apk/com.aniplex.fategrandorder.en.apk"

# URL for the version information
url_version = "https://gplay-ver.atlasacademy.workers.dev/?id=com.aniplex.fategrandorder.en"

# Temp folder for downloads
temp_folder = os.path.join(os.getcwd(), "temp")

def ensure_temp_folder_exists(folder_path):
    """
    Ensure the temporary folder exists.
    
    Args:
        folder_path (str): Path to the folder to be created if it doesn't exist.
    """
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

def download_file(url, destination):
    """
    Download a file from a URL to a local destination.
    
    Args:
        url (str): URL of the file to download.
        destination (str): Path where the downloaded file will be saved.
    
    Raises:
        Exception: If the download fails.
    """
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(destination, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
        print(f"Downloaded file to {destination}")
    except Exception as e:
        print(f"Failed to download file from {url}. Error: {e}")

def get_version_info(url):
    """
    Get version information from a URL.
    
    Args:
        url (str): URL to fetch version information from.
    
    Returns:
        str: Version information if available, otherwise an error message.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except Exception as e:
        return f"Failed to fetch version info from {url}. Error: {e}"

def main():
    ensure_temp_folder_exists(temp_folder)
    
    apk_destination = os.path.join(temp_folder, "fgo.apk")
    download_file(url_apk, apk_destination)
    
    version_info = get_version_info(url_version)
    print(f"Version Info: {version_info}")

if __name__ == "__main__":
    main()
