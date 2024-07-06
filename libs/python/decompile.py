import os
import subprocess
import sys
import config

def decompile_apk():
    """
    Decompile the APK file using apktool.
    """
    apktool = os.path.join(os.getcwd(), "libs", "java", "apktool.jar")
    apk = os.path.join(config.temp_folder, "fate.apk")

    print('[App] Decompiling APK...', file=sys.stdout)
    try:
        subprocess.run(
            f"java -jar {apktool} d {apk} --output ./temp/files/ -f",
            check=True,
            shell=True
        )
        print('[App] Decompilation completed successfully!', file=sys.stdout)
    except subprocess.CalledProcessError as e:
        print(f'[App] Decompilation failed: {e}', file=sys.stderr)

def decrypt():
    """
    Decrypt the files using Il2CppDumper.
    """
    il2cpp = os.path.join(os.getcwd(), "libs", "Il2CppDumper", "Il2CppDumper-x86.exe")
    global_metadata = os.path.join(config.temp_folder, "files", "assets", "bin", "Data", "Managed", "Metadata", "global-metadata.dat")
    libil2cpp = os.path.join(config.temp_folder, "files", "lib", "armeabi-v7a", "libil2cpp.so")
    decrypt_folder = os.path.join(config.temp_folder, "decrypt")

    print('[App] Decrypting files...', file=sys.stdout)
    try:
        p = subprocess.Popen(
            f"{il2cpp} {libil2cpp} {global_metadata} {decrypt_folder}",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True
        )
        stdout, stderr = p.communicate(input=b'\n')
        if p.returncode == 0:
            print('[App] Decryption completed successfully!', file=sys.stdout)
        else:
            print(f'[App] Decryption failed: {stderr.decode()}', file=sys.stderr)
    except Exception as e:
        print(f'[App] Decryption encountered an error: {e}', file=sys.stderr)

if __name__ == "__main__":
    decompile_apk()
    decrypt()
