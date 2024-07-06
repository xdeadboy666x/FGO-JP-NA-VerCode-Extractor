import os
import requests
import logging

# URL for the APK file
url_apk = "https://fgo.square.ovh/apk/com.aniplex.fategrandorder.apk"

# URL for the version information
url_version = "https://gplay-ver.atlasacademy.workers.dev/?id=com.aniplex.fategrandorder"

# Temp folder for downloads
temp_folder = os.path.join(os.getcwd(), "temp")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def ensure_temp_folder_exists(folder_path):
    """
    Ensure the temporary folder exists.
    
    Args:
        folder_path (str): Path to the folder to be created if it doesn't exist.
    """
    try:
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
    except Exception as e:
        logger.error(f"Failed to create temporary folder {folder_path}. Error: {e}")
        raise

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
        logger.info(f"Downloaded file to {destination}")
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error occurred while downloading file from {url}. Error: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to download file from {url}. Error: {e}")
        raise

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
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error occurred while fetching version info from {url}. Error: {e}")
        raise
    except Exception as e:
        logger.error(f"Failed to fetch version info from {url}. Error: {e}")
        raise

def main():
    ensure_temp_folder_exists(temp_folder)
    
    apk_destination = os.path.join(temp_folder, "fgo.apk")
    try:
        download_file(url_apk, apk_destination)
    except Exception as e:
        logger.error(f"Failed to download APK file. Error: {e}")
        return
    
    try:
        version_info = get_version_info(url_version)
        logger.info(f"Version Info: {version_info}")
    except Exception as e:
        logger.error(f"Failed to fetch version information. Error: {e}")
        return

if __name__ == "__main__":
    main()
