#!/usr/bin/env python3
import subprocess
import os
import sys
import time
import struct
from pathlib import Path
from dataclasses import dataclass
from enum import IntEnum

TARGET_DIR = "xxnuo/projects/test-filemonitor/target"
SUBVOL_PATH = Path("/home")


class BtrfsSendCmd(IntEnum):
    BTRFS_SEND_C_UNSPEC = 0
    BTRFS_SEND_C_SUBVOL = 1
    BTRFS_SEND_C_SNAPSHOT = 2
    BTRFS_SEND_C_MKFILE = 3
    BTRFS_SEND_C_MKDIR = 4
    BTRFS_SEND_C_MKNOD = 5
    BTRFS_SEND_C_MKFIFO = 6
    BTRFS_SEND_C_MKSOCK = 7
    BTRFS_SEND_C_SYMLINK = 8
    BTRFS_SEND_C_RENAME = 9
    BTRFS_SEND_C_LINK = 10
    BTRFS_SEND_C_UNLINK = 11
    BTRFS_SEND_C_RMDIR = 12
    BTRFS_SEND_C_SET_XATTR = 13
    BTRFS_SEND_C_REMOVE_XATTR = 14
    BTRFS_SEND_C_WRITE = 15
    BTRFS_SEND_C_CLONE = 16
    BTRFS_SEND_C_TRUNCATE = 17
    BTRFS_SEND_C_CHMOD = 18
    BTRFS_SEND_C_CHOWN = 19
    BTRFS_SEND_C_UTIMES = 20
    BTRFS_SEND_C_END = 21
    BTRFS_SEND_C_UPDATE_EXTENT = 22


CMD_NAMES = {
    BtrfsSendCmd.BTRFS_SEND_C_MKFILE: "CREATE_FILE",
    BtrfsSendCmd.BTRFS_SEND_C_MKDIR: "CREATE_DIR",
    BtrfsSendCmd.BTRFS_SEND_C_RENAME: "RENAME",
    BtrfsSendCmd.BTRFS_SEND_C_LINK: "LINK",
    BtrfsSendCmd.BTRFS_SEND_C_UNLINK: "DELETE_FILE",
    BtrfsSendCmd.BTRFS_SEND_C_RMDIR: "DELETE_DIR",
    BtrfsSendCmd.BTRFS_SEND_C_WRITE: "WRITE",
    BtrfsSendCmd.BTRFS_SEND_C_TRUNCATE: "TRUNCATE",
    BtrfsSendCmd.BTRFS_SEND_C_CHMOD: "CHMOD",
    BtrfsSendCmd.BTRFS_SEND_C_CHOWN: "CHOWN",
    BtrfsSendCmd.BTRFS_SEND_C_UTIMES: "UTIMES",
    BtrfsSendCmd.BTRFS_SEND_C_UPDATE_EXTENT: "UPDATE_EXTENT",
}


class BtrfsSendAttr(IntEnum):
    BTRFS_SEND_A_UNSPEC = 0
    BTRFS_SEND_A_UUID = 1
    BTRFS_SEND_A_CTRANSID = 2
    BTRFS_SEND_A_INO = 3
    BTRFS_SEND_A_SIZE = 4
    BTRFS_SEND_A_MODE = 5
    BTRFS_SEND_A_UID = 6
    BTRFS_SEND_A_GID = 7
    BTRFS_SEND_A_RDEV = 8
    BTRFS_SEND_A_CTIME = 9
    BTRFS_SEND_A_MTIME = 10
    BTRFS_SEND_A_ATIME = 11
    BTRFS_SEND_A_OTIME = 12
    BTRFS_SEND_A_XATTR_NAME = 13
    BTRFS_SEND_A_XATTR_DATA = 14
    BTRFS_SEND_A_PATH = 15
    BTRFS_SEND_A_PATH_TO = 16
    BTRFS_SEND_A_PATH_LINK = 17
    BTRFS_SEND_A_FILE_OFFSET = 18
    BTRFS_SEND_A_DATA = 19
    BTRFS_SEND_A_CLONE_UUID = 20
    BTRFS_SEND_A_CLONE_CTRANSID = 21
    BTRFS_SEND_A_CLONE_PATH = 22
    BTRFS_SEND_A_CLONE_OFFSET = 23
    BTRFS_SEND_A_CLONE_LEN = 24


@dataclass
class Change:
    cmd: str
    path: str
    path_to: str = None


def parse_send_stream(data: bytes) -> list[Change]:
    changes = []
    pos = 0

    if len(data) < 17:
        return changes

    magic = data[0:13]
    if magic != b"btrfs-stream\x00":
        print(f"Invalid magic: {magic}")
        return changes

    struct.unpack("<I", data[13:17])[0]
    pos = 17

    while pos < len(data):
        if pos + 10 > len(data):
            break

        cmd_len = struct.unpack("<I", data[pos : pos + 4])[0]
        cmd_type = struct.unpack("<H", data[pos + 4 : pos + 6])[0]
        pos += 10

        if cmd_len == 0:
            continue

        attr_end = pos + cmd_len - 4
        attrs = {}

        while pos < attr_end:
            if pos + 4 > len(data):
                break
            attr_type = struct.unpack("<H", data[pos : pos + 2])[0]
            attr_len = struct.unpack("<H", data[pos + 2 : pos + 4])[0]
            pos += 4

            if pos + attr_len > len(data):
                break

            attr_data = data[pos : pos + attr_len]
            pos += attr_len

            if attr_type == BtrfsSendAttr.BTRFS_SEND_A_PATH:
                attrs["path"] = attr_data.rstrip(b"\x00").decode(
                    "utf-8", errors="replace"
                )
            elif attr_type == BtrfsSendAttr.BTRFS_SEND_A_PATH_TO:
                attrs["path_to"] = attr_data.rstrip(b"\x00").decode(
                    "utf-8", errors="replace"
                )

        if cmd_type in CMD_NAMES and "path" in attrs:
            changes.append(
                Change(
                    cmd=CMD_NAMES[cmd_type],
                    path=attrs.get("path", ""),
                    path_to=attrs.get("path_to"),
                )
            )

    return changes


def create_snapshot(subvol: Path, snapshot_path: Path):
    subprocess.run(
        [
            "sudo",
            "btrfs",
            "subvolume",
            "snapshot",
            "-r",
            str(subvol),
            str(snapshot_path),
        ],
        check=True,
        capture_output=True,
    )


def delete_snapshot(snapshot_path: Path):
    subprocess.run(
        ["sudo", "btrfs", "subvolume", "delete", str(snapshot_path)],
        check=True,
        capture_output=True,
    )


def get_send_diff(parent_snap: Path, child_snap: Path) -> bytes:
    result = subprocess.run(
        ["sudo", "btrfs", "send", "--no-data", "-p", str(parent_snap), str(child_snap)],
        capture_output=True,
    )
    return result.stdout


def check_btrfs():
    result = subprocess.run(
        ["df", "--type=btrfs", str(SUBVOL_PATH)], capture_output=True
    )
    if result.returncode != 0:
        print(f"Error: {SUBVOL_PATH} is not on a Btrfs filesystem")
        sys.exit(1)


def is_in_target(path: str) -> bool:
    return path.startswith(TARGET_DIR) or path.startswith(TARGET_DIR + "/")


def monitor(interval: float = 5.0):
    check_btrfs()

    snap_dir = SUBVOL_PATH / ".btrfs_monitor_snaps"
    snap_dir.mkdir(exist_ok=True)
    snap_count = 0
    prev_snap = None

    print("Btrfs Send Monitor started")
    print(f"Monitoring: {SUBVOL_PATH}")
    print(f"Filter: {TARGET_DIR}")
    print(f"Snapshot dir: {snap_dir}")
    print(f"Interval: {interval}s")
    print("-" * 50)

    try:
        while True:
            curr_snap = snap_dir / f"snap_{snap_count}"

            try:
                create_snapshot(SUBVOL_PATH, curr_snap)
            except subprocess.CalledProcessError as e:
                print(f"Failed to create snapshot: {e}")
                time.sleep(interval)
                continue

            if prev_snap and prev_snap.exists():
                try:
                    diff_data = get_send_diff(prev_snap, curr_snap)
                    changes = parse_send_stream(diff_data)

                    for change in changes:
                        if not is_in_target(change.path):
                            continue
                        if change.path_to:
                            print(f"[{change.cmd}] {change.path} -> {change.path_to}")
                        else:
                            print(f"[{change.cmd}] {change.path}")

                except subprocess.CalledProcessError as e:
                    print(f"Failed to get diff: {e}")

                try:
                    delete_snapshot(prev_snap)
                except Exception:
                    pass

            prev_snap = curr_snap
            snap_count += 1
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        if prev_snap and prev_snap.exists():
            try:
                delete_snapshot(prev_snap)
            except Exception:
                pass
        try:
            snap_dir.rmdir()
        except Exception:
            pass


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Note: This script requires sudo for btrfs operations")
    monitor()
