import os

url_apk = (
    "https://static.atlasacademy.io/apk/com.aniplex.fategrandorder.en.combined.xapk"
)

url_version = (
    "https://gplay-ver.atlasacademy.workers.dev/?id=com.aniplex.fategrandorder.en"
)

apk_name = url_apk.split("/")[-1]

temp_folder = os.path.join(os.getcwd(), "temp")
