import subprocess
import shutil
import os
import mmap
import os
import sys
import urllib.request
import requests
import threading
import time
import hashlib
import shutil
import struct

CDN = "ph.prd.cdnfiles"


def calculate_file_hash(id):
    hash2 = md5_hash(f"{CDN}/{id}")
    idx = int(hash2[:1], 16)
    hash2 = hash2[idx:] + hash2[:idx]
    return md5_hash(hash2)


def md5_hash(value):
    md5 = hashlib.md5()
    md5.update(value.encode('utf-8'))
    return md5.hexdigest()


def get_file_size(url):
    # Open the URL
    with urllib.request.urlopen(url) as response:
        # Get the size of the file
        file_size = int(response.headers["Content-Length"])
        return file_size


def print_cube(num):
    count = 0
    verId = []
    for i in range(0, 111000, 100):
        mdver = 50000 + i
        url = f'https://resource.pokemon-home.com/{str(calculate_file_hash(mdver))}/md/dro/diff/MD_AssetbundleDLPackVer.snd'
        if count > 20:
            break
        try:
            urllib.request.urlopen(url)
            count += 1
            verId.append(mdver)
        except urllib.error.HTTPError as e:
            # Return code error (e.g. 404, 501, ...)
            # ...
            count += 1
            continue
        except urllib.error.URLError as e:
            # Not an HTTP-specific error (e.g. connection refused)
            # ...
            count += 1
            continue
        else:
            count += 1
            continue
    version = verId[-1]
    download_url = f'https://resource.pokemon-home.com/{str(calculate_file_hash(version))}/md/dro/diff/MD_AssetbundleDLPackVer.snd'
    download_folder = "downloaded_files"
    if not os.path.exists(download_folder):
        os.makedirs(download_folder)
    download_path = os.path.join(download_folder, "MD_AssetbundleDLPackVer.snd")
    urllib.request.urlretrieve(download_url, download_path)

def Hash(id):
    hash = hashlib.md5(f"{CDN}/{id}".encode('utf-8')).hexdigest()
    idx = int(hash[:1], 16)
    d = hash[idx:] + hash[:idx]
    return hashlib.md5(d.encode('utf-8')).hexdigest()

class BinaryReader:
    def __init__(self, file):
        self.file = file

    def read_string(self, length = None):
        length = self.read_char() if not length else length
        return self.file.read(length).decode("utf-8")

    def read_bytes(self, length):
        return self.file.read(length)

    def read_char(self):
        return struct.unpack(">b", self.file.read(1))[0]

    def read_int(self):
        return struct.unpack("<i", self.file.read(4))[0]



if __name__ == "__main__":
    # creating thread
    t1 = threading.Thread(target=print_cube, args=(31,))

    # starting thread 1
    t1.start()

    # wait until thread 1 is completely executed
    t1.join()

    # both threads completely executed
file_path = "downloaded_files/MD_AssetbundleDLPackVer.snd"

with open(file_path, "rb") as f:
    reader = BinaryReader(f)
    reader.read_bytes(4)
    assets_len = reader.read_int()
    reader.read_bytes(8)
    assets = []
    for i in range(assets_len):
        nm = reader.read_string()
        sa = reader.read_int()
        si = reader.read_int()
        vr_ios = reader.read_int()
        vr_dro = reader.read_int()
        a = reader.read_char()
        file_len = int(reader.read_string(a).replace("@", ""))
        filenames = [reader.read_string() for _ in range(file_len)]
        assets.append({"nm": nm, "sa": sa, "si": si, "vr_ios": vr_ios, "vr_dro": vr_dro, "files": filenames})

    url_list = [f"https://resource.pokemon-home.com/{Hash(e['vr_dro'])}/dro/{e['nm']}.abap" for e in assets]

    if not os.path.exists("downloaded_files"):
        os.makedirs("downloaded_files")

    # download ABA_Decryptor.exe
    decryptor_url = "https://github.com/FlicksDaModdle/important-files/raw/main/ABA_Decryptor.exe"
    decryptor_file_path = os.path.join("downloaded_files", "ABA_Decryptor.exe")
    response = requests.get(decryptor_url)
    open(decryptor_file_path, "wb").write(response.content)

    # prompt user for specific number to download
    number = input(
        "Enter the pokemon ID that you want to download(0094) for example. If you want to clear all files, type 'clear', or type 'all' to download all files. Option: ")
    if number == "clear":
        # Delete all files in "downloaded_files"
        shutil.rmtree("downloaded_files", ignore_errors=True)
        print("All files in 'downloaded_files' have been deleted.")
        sys.exit()
    if number == "all":
        files_to_download = assets
    else:
        files_to_download = [e for e in assets if number in e['nm']]

    # download and decrypt each .abap file for the selected number
    for file_to_download in files_to_download:
        url = f"https://resource.pokemon-home.com/{Hash(file_to_download['vr_dro'])}/dro/{file_to_download['nm']}.abap"
        response = requests.get(url)
        abap_file_name = url.split('/')[-1]
        temp_file_path = os.path.join("downloaded_files", abap_file_name)
        open(temp_file_path, "wb").write(response.content)
        subprocess.call([decryptor_file_path, temp_file_path, os.path.join("downloaded_files", abap_file_name)])
        os.remove(temp_file_path)
    # delete ABA_Decryptor.exe file
    decryptor_file_path = os.path.join("downloaded_files", "ABA_Decryptor.exe")
    os.remove(decryptor_file_path)
os.remove(file_path)