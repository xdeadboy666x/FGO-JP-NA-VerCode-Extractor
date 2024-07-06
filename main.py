import sys
import logging
from libs.python.update import check_update
from libs.python.download import download_latest
from libs.python.decompile import decompile_apk, decrypt
from libs.python.verCode import write_verCode_data

def setup_logging():
    """
    Setup logging configuration.
    """
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('app.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def main():
    """
    Main function to run the workflow for updating, downloading, decompiling,
    decrypting, and writing version code data for the application.
    """
    try:
        setup_logging()
        if check_update():
            logging.info('[App] Starting update process...')
            download_latest()
            decompile_apk()
            decrypt()
            write_verCode_data()
            logging.info('[App] Workflow completed successfully.')
        else:
            logging.info('[App] No update available. Workflow canceled.')
    except FileNotFoundError as e:
        logging.error(f'[App] File not found error: {e}')
    except Exception as e:
        logging.error(f'[App] Workflow failed due to an error: {e}', exc_info=True)

if __name__ == "__main__":
    main()
