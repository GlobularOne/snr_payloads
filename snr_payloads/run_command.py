"""
Payload allowing you to run a command or executable on boot
"""

from libsnr.util.common_utils import print_error
from libsnr.util.payloads.autorun import Autorun
from snr.variables import global_vars

LICENSE = "Apache-2.0"
AUTHORS = ["GlobularOne"]
INPUTS = (
    "COMMAND",
)

def load():
    global_vars.set_variable("COMMAND", "", info_description="Command to run")
    return 0

def unload():
    for inp in INPUTS:
        global_vars.del_variable(inp)

def generate(context: dict):
    command = global_vars.get_variable("COMMAND")
    assert isinstance(command, str)
    if len(command) == 0:
        print_error("No command set to run")
        return 1
    autorun = Autorun(context)
    autorun.add_executable(command, "command")
    autorun.write()
    return 0
