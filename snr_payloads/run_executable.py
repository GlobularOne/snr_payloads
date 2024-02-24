"""
Payload allowing you to copy and run an executable on boot
"""
import os
import shutil

from libsnr.util.common_utils import print_debug, print_error
from libsnr.util.payloads.autorun import Autorun
from snr.variables import global_vars

LICENSE = "Apache-2.0"
AUTHORS = ["GlobularOne"]
INPUTS = (
    "EXECUTABLES",
)

def load():
    global_vars.set_variable("EXECUTABLES", [], info_description="Executables to run")
    return 0

def unload():
    for inp in INPUTS:
        global_vars.del_variable(inp)

def generate(context: dict):
    executables = global_vars.get_variable("EXECUTABLES") 
    assert isinstance(executables, list)
    if len(executables) == 0:
        print_error("No executables set to run")
        return 1
    autorun = Autorun(context)
    for executable in executables:
        basename = os.path.basename(executable)
        target = os.path.join("root", basename)
        print_debug(f"Copying '{executable}' to '{target}'")
        try:
            shutil.copyfile(executable, os.path.join(context["temp_dir"], target))
        except Exception as exc:  # pylint: disable=broad-exception-caught
            print_error(f"Installing executable to rootfs failed: {exc}")
            return 1
        print_debug(f"Adding autorun service for '{executable}'")
        autorun.add_executable("/" + target)
    autorun.write()
    return 0
