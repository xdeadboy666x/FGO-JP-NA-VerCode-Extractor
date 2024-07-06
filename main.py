from libs.python.update import check_update
from libs.python.download import download_latest
from libs.python.decompile import decompile_apk, decrypt
from libs.python.verCode import write_verCode_data

import sys

def main():
    """
    Main function to run the workflow for updating, downloading, decompiling,
    decrypting, and writing version code data for the application.
    """
    try:
        if check_update():
            download_latest()
            decompile_apk()
            decrypt()
            write_verCode_data()
        else:
            print('[App] Workflow Canceled!', file=sys.stdout)
    except Exception as e:
        print(f'[App] Workflow failed due to an error: {e}', file=sys.stderr)

if __name__ == "__main__":
    main()
