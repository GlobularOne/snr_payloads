"""
Payload that scans all disks for linux partitions and manage users and group.
Add an asterisk to a uid or gid to reference by uid or gid and not username or group name
Example:
    set USERS -*1001;user12;-user13
To add a user named myuser with password, mypassword:
    set USERS myuser
    set PAIRS myuser:mypassword
If a user is added using USERS and it's password is not changed. The default password is: Aa12!aaaaaaaaa

"""
from libsnr import version as libsnr_version
from libsnr.util.common_utils import print_error, rootfs_open
from libsnr.util.payloads.autorun import Autorun
from snr.variables import global_vars

LICENSE = "Apache-2.0"
AUTHORS = ["GlobularOne"]
INPUTS = (
    "PAIRS", "USERS", "GROUPS", "ADD_TO", "REMOVE_FROM", "SHELLS", "UNLOCK", "PASSPHRASES"
)

PAYLOAD = r"""#!/usr/bin/python3
import os
import time

from libsnr.payload import unix_group, unix_passwd
from libsnr.payload.context import create_context_for_mountpoint
from libsnr.payload.data_dir import data_mkdir, data_open, fix_data_dir
from libsnr.payload.safety_pin import require_lack_of_safety_pin
from libsnr.payload.storage import (get_partition_root, luks_close,
                                    luks_is_partition_encrypted, luks_open,
                                    lvm_activate_all_vgs, lvm_scan_all,
                                    query_all_block_info, query_all_partitions)
from libsnr.util.chroot_program_wrapper import PIPE, ChrootProgramWrapper
from libsnr.util.common_utils import (print_error, print_info, print_ok,
                                      print_warning)
from libsnr.util.programs.mount import Mount
from libsnr.util.programs.umount import Umount

PAIRS = []
USERS = []
GROUPS = []
ADD_TO = []
REMOVE_FROM = []
SHELLS = []
UNLOCK = []
PASSPHRASES = []

FS_MOUNTPOINT = "/mnt"
DEFAULT_PASSWORD = "Aa12!aaaaaaaaa"


def lookup_username_by_uid(uid):
    passwd = unix_passwd.parse_unix_passwd_file(FS_MOUNTPOINT)
    for entry in passwd:
        if str(entry.uid) == str(uid):
            return entry.login_name
    print_warning(f"Looking up user by UID ({uid}) failed!")
    return ""


def lookup_group_name_by_gid(gid):
    group = unix_group.parse_unix_group_file(FS_MOUNTPOINT)
    for entry in group:
        if str(entry.gid) == str(gid):
            return entry.group_name
    print_warning(f"Looking up group by GID ({gid}) failed!")
    return ""


def backup_login_info(part: str, suffix=".before"):
    for file in ("passwd", "shadow", "group", "gshadow"):
        with open(f"/{FS_MOUNTPOINT}/etc/{file}") as stream:
            data = stream.read()
        with data_open(os.path.join(part.replace("/", ".")[1:], file + suffix), "w") as stream2:
            stream2.write(data)


def main():
    require_lack_of_safety_pin()
    lvm_scan_all()
    lvm_activate_all_vgs()
    block_info = query_all_block_info()
    fix_data_dir()
    print_ok("Unix_user_management payload started")
    root_context = create_context_for_mountpoint("/")
    if root_context is None:
        print_error("Creating context for / failed")
        return
    our_device = get_partition_root(root_context["device"], block_info)
    if our_device is None:
        print_error("Finding partition root device for / failed")
        return
    for part in query_all_partitions(block_info):
        if get_partition_root(part, block_info) == our_device:
            continue
        luks_encrypted = luks_is_partition_encrypted(part)
        luks_name = part.split(os.path.sep)[-1] + "_crypt"
        if luks_encrypted:
            print_info(
                "Luks encrypted partition found! Trying available passphrases...")
            for passphrase in PASSPHRASES:
                if luks_open(part, luks_name, passphrase):
                    print_info("Luks partition opened!")
                    break
            else:
                try:
                    print_warning(
                        "Passphrase not found! Press Ctrl + C to try a passphrase")
                    time.sleep(5)
                except KeyboardInterrupt:
                    try:
                        while True:
                            print_info(
                                "Enter new passphrase or press Ctrl + C again to abort: ", end="")
                            passphrase = input()
                            if luks_open(part, luks_name, passphrase):
                                print_info("Luks partition opened!")
                                break
                    except KeyboardInterrupt:
                        print_warning(
                            f"No passphrase found for partition '{part}', ignoring partition.")
                        continue
            part = f"/dev/mapper/{luks_name}"
        # Try to mount it and see if it sounds like something like unix
        errorcode = Mount().invoke_and_wait(None, part, FS_MOUNTPOINT)
        if errorcode != 0:
            print_error(
                f"Failed to mount partition '{part}'! Skipping partition")
            if luks_encrypted:
                luks_close(luks_name)
            continue
        if os.path.exists(f"/{FS_MOUNTPOINT}/usr/sbin/init") or os.path.exists(f"/{FS_MOUNTPOINT}/usr/bin/init"):
            data_mkdir(part.replace("/", ".")[1:])
            # Take a copy of passwd,shadow,group and gshadow files
            print_info("Backing up user and group data (before version)")
            backup_login_info(part)
            # The order we should change things:
            # 1. USERS
            # 2. PAIRS
            # 3. SHELLS
            # 4. UNLOCK
            # 5. GROUPS
            # 6. ADD_TO
            # 7. REMOVE_FROM
            # This way, we cannot end up breaking ourselves
            context = create_context_for_mountpoint(FS_MOUNTPOINT)
            if context is None:
                print_warning(
                    "Creating context for partition failed! Ignoring filesystem")
                if luks_encrypted:
                    luks_close(luks_name)
                continue
            # USERS
            for username in USERS:
                if username.startswith("-"):
                    username = username[1:]
                    if username.startswith("*"):
                        # Referenced by UID, not username. Find the username and continue
                        username = lookup_username_by_uid(username[1:])
                        if len(username) == 0:
                            continue
                        print_info(f"Deleting user '{username}'")
                        errorcode = ChrootProgramWrapper(
                            context, "deluser", stdout=PIPE).invoke_and_wait(None, username)
                        if errorcode != 0:
                            print_warning(
                                f"Deleting user '{username}' failed!")
                else:
                    print_info(f"Adding user '{username}'")
                    adduser = ChrootProgramWrapper(
                        context, "adduser", stdin=PIPE, stdout=PIPE)
                    adduser.invoke(username)
                    assert adduser.stdin is not None
                    adduser.stdin.write(DEFAULT_PASSWORD)
                    for _ in range(6):
                        adduser.stdin.write("\n")
                    errorcode = adduser.wait(None)
                    if errorcode != 0:
                        print_warning(f"Adding user '{username}' failed!")
            # PAIRS
            for user_data in PAIRS:
                user, password = user_data.split(";", maxsplit=1)
                if user.startswith("*"):
                    user = lookup_username_by_uid(user[1:])
                    if len(user) == 0:
                        continue
                print_info(f"Changing password of '{user}'")
                chpasswd = ChrootProgramWrapper(
                    context, "chpasswd", stdin=PIPE)
                chpasswd.invoke()
                assert chpasswd.stdin is not None
                chpasswd.stdin.write(f"{user}:{password}\n")
                chpasswd.stdin.close()
                errorcode = chpasswd.wait(None)
                if errorcode != 0:
                    print_warning(f"Changing password for '{user}' failed!")
            # SHELLS
            for user_shell in SHELLS:
                user, shell = user_shell.split(":", maxsplit=1)
                if user.startswith("*"):
                    user = lookup_username_by_uid(user[1:])
                    if len(user) == 0:
                        continue
                    print_info(f"Changing default shell of '{user}'")
                    errorcode = ChrootProgramWrapper(context, "chsh").invoke_and_wait(None, user,
                                                                                      options={
                                                                                          "shell": shell
                                                                                      })
                    if errorcode != 0:
                        print_warning(
                            f"Changing default shell of 'user '{user}' failed!")
            # UNLOCK
            for user in UNLOCK:
                if user.startswith("-"):
                    if user.startswith("*"):
                        user = lookup_username_by_uid(user[1:])
                        if len(user) == 0:
                            continue
                    print_info(f"Locking user '{user}'")
                    errorcode = ChrootProgramWrapper(context, "usermod").invoke_and_wait(None, user,
                                                                                         options={
                                                                                             "lock": None
                                                                                         })
                    if errorcode != 0:
                        print_warning(f"Locking user '{user}' failed!")
                else:
                    if user.startswith("*"):
                        user = lookup_username_by_uid(user[1:])
                        if len(user) == 0:
                            continue
                    print_info(f"Unlocking user '{user}'")
                    errorcode = ChrootProgramWrapper(context, "usermod").invoke_and_wait(None, user,
                                                                                         options={
                                                                                             "unlock": None
                                                                                         })
                    if errorcode != 0:
                        print_warning(f"Unlocking user '{user}' failed!")
            # GROUPS
            for group_name in GROUPS:
                if group_name.startswith("-"):
                    group_name = group_name[1:]
                    if group_name.startswith("*"):
                        # Referenced by GID, not group name. Find the group name and continue
                        group_name = lookup_group_name_by_gid(group_name[1:])
                        if len(group_name) == 0:
                            continue
                        print_info(f"Deleting group '{group_name}'")
                        errorcode = ChrootProgramWrapper(
                            context, "delgroup", stdout=PIPE).invoke_and_wait(None, group_name)
                        if errorcode != 0:
                            print_warning(
                                f"Deleting group '{group_name}' failed!")
                else:
                    print_info(f"Adding group '{group_name}'")
                    errorcode = ChrootProgramWrapper(
                        context, "addgroup", stdout=PIPE).invoke_and_wait(None, group_name)
                    if errorcode != 0:
                        print_warning(f"Adding group '{group_name}' failed!")
            # ADD_TO
            for user_data in ADD_TO:
                user, group = user_data.split(":", maxsplit=1)
                if user.startswith("*"):
                    user = lookup_username_by_uid(user[1:])
                    if len(user) == 0:
                        continue
                if group.startswith("*"):
                    group = lookup_group_name_by_gid(group[1:])
                    if len(group) == 0:
                        continue
                print_info(f"Adding user '{user}' to group '{group}'")
                errorcode = ChrootProgramWrapper(
                    context, "adduser").invoke_and_wait(None, user, group)
                if errorcode != 0:
                    print_warning(
                        f"Adding user '{user}' to group '{group}' failed!")
            # REMOVE_FROM
            for user_data in ADD_TO:
                user, group = user_data.split(":", maxsplit=1)
                if user.startswith("*"):
                    user = lookup_username_by_uid(user[1:])
                    if len(user) == 0:
                        continue
                if group.startswith("*"):
                    group = lookup_group_name_by_gid(group[1:])
                    if len(group) == 0:
                        continue
                print_info(f"Removing user '{user}' from group '{group}'")
                errorcode = ChrootProgramWrapper(
                    context, "deluser").invoke_and_wait(None, user, group)
                if errorcode != 0:
                    print_warning(
                        f"Removing user {user} from group {group} failed!")
            print_info("Backing up user and group data (after version)")
            backup_login_info(part, suffix=".after")
            print_ok("")
        Umount().invoke_and_wait(None, FS_MOUNTPOINT)
        if luks_encrypted:
            luks_close(luks_name)
    print_ok("Unix_user_management payload completed")


if __name__ == "__main__":
    main()
"""


def load():
    if int(libsnr_version.MAJOR) == 0 and int(libsnr_version.MINOR) < 1:
        print_error("This payload requires libsnr version above 0.1.0")
        return 1
    global_vars.set_variable(
        "PAIRS", [], -1, "User:Password pairs, Changes user's password")
    global_vars.set_variable(
        "USERS", [], -1, "List of users to add or delete, -<USERNAME> deletes a user")
    global_vars.set_variable(
        "GROUPS", [], -1, "List of groups to add or delete, -<USERNAME> deletes a group")
    global_vars.set_variable(
        "ADD_TO", [], -1, "User:Group pairs, add User to Group")
    global_vars.set_variable(
        "REMOVE_FROM", [], -1, "User:Group pairs, remove User from Group")
    global_vars.set_variable(
        "SHELLS", [], -1, "User:Shell pairs, makes User use Shell as it's default shell")
    global_vars.set_variable(
        "UNLOCK", [], -1, "List of users to unlock, -<USERNAME> will lock it instead")
    global_vars.set_variable(
        "PASSPHRASES", [], -1, "Passphrases to try for LUKS-encrypted partitions"
    )
    return 0


def unload():
    for inp in INPUTS:
        global_vars.del_variable(inp)


def generate(context: dict):
    for inp in INPUTS:
        tmp = global_vars.get_variable(inp)
        assert isinstance(tmp, list)
        if len(tmp):
            break
    else:
        print_error("Nothing to do")
        return 1
    payload = PAYLOAD
    with rootfs_open(context, "root/user_management.py", "w") as stream:
        for inp in INPUTS:
            value = global_vars.get_variable(inp)
            payload = payload.replace(f"{inp} = []", f"{inp} = {repr(value)}")
        stream.write(payload)
    autorun = Autorun(context)
    autorun.add_executable("python3 /root/user_management.py", "snr_payload")
    autorun.write()
