import os

# https://fgo.square.ovh/apk/com.aniplex.fategrandorder.en.apk
url_apk = "https://storage.evozi.com/apk/dl/17/06/25/com.aniplex.fategrandorder.en_131.apk"

# https://gplay-ver.atlasacademy.workers.dev/?id=com.aniplex.fategrandorder
url_version = (
    "https://play.google.com/store/apps/details?id=com.aniplex.fategrandorder.en&device=phone"
)

apk_name = url_apk.split("/")[-1]

# Temp folder
temp_folder = os.path.join(os.getcwd(), "temp")
