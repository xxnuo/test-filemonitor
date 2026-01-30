#!/usr/bin/env python3
import os
import sys
import struct
import ctypes
import ctypes.util
import subprocess
import threading
import time
from pathlib import Path
from dataclasses import dataclass
from enum import IntEnum

TARGET_DIR = "/home/xxnuo/projects/test-filemonitor/target"
SUBVOL_PATH = Path("/home")
DEBOUNCE_SECONDS = 30.0

FAN_CLASS_NOTIF = 0x00000000
FAN_CLOEXEC = 0x00000001
FAN_REPORT_FID = 0x00000200
FAN_REPORT_DIR_FID = 0x00000400
FAN_REPORT_NAME = 0x00000800

FAN_MARK_ADD = 0x00000001

FAN_MODIFY = 0x00000002
FAN_ATTRIB = 0x00000004
FAN_CLOSE_WRITE = 0x00000008
FAN_MOVED_FROM = 0x00000040
FAN_MOVED_TO = 0x00000080
FAN_CREATE = 0x00000100
FAN_DELETE = 0x00000200
FAN_ONDIR = 0x40000000
FAN_EVENT_ON_CHILD = 0x08000000

AT_FDCWD = -100


class BtrfsSendCmd(IntEnum):
    BTRFS_SEND_C_MKFILE = 3
    BTRFS_SEND_C_MKDIR = 4
    BTRFS_SEND_C_RENAME = 9
    BTRFS_SEND_C_LINK = 10
    BTRFS_SEND_C_UNLINK = 11
    BTRFS_SEND_C_RMDIR = 12
    BTRFS_SEND_C_WRITE = 15
    BTRFS_SEND_C_TRUNCATE = 17
    BTRFS_SEND_C_CHMOD = 18
    BTRFS_SEND_C_CHOWN = 19
    BTRFS_SEND_C_UTIMES = 20
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
    BTRFS_SEND_A_PATH = 15
    BTRFS_SEND_A_PATH_TO = 16


@dataclass
class Change:
    cmd: str
    path: str
    path_to: str = None


libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def fanotify_init(flags, event_f_flags):
    ret = libc.syscall(300, flags, event_f_flags)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return ret


def fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname):
    if pathname:
        pathname = pathname.encode() if isinstance(pathname, str) else pathname
    ret = libc.syscall(301, fanotify_fd, flags, mask, dirfd, pathname)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return ret


def parse_send_stream(data: bytes) -> list[Change]:
    changes = []
    pos = 0

    if len(data) < 17:
        return changes

    magic = data[0:13]
    if magic != b"btrfs-stream\x00":
        return changes

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
                attrs["path"] = attr_data.rstrip(b"\x00").decode("utf-8", errors="replace")
            elif attr_type == BtrfsSendAttr.BTRFS_SEND_A_PATH_TO:
                attrs["path_to"] = attr_data.rstrip(b"\x00").decode("utf-8", errors="replace")

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
        ["sudo", "btrfs", "subvolume", "snapshot", "-r", str(subvol), str(snapshot_path)],
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
    result = subprocess.run(["df", "--type=btrfs", str(SUBVOL_PATH)], capture_output=True)
    if result.returncode != 0:
        print(f"Error: {SUBVOL_PATH} is not on a Btrfs filesystem")
        sys.exit(1)


class DebouncedBtrfsSync:
    def __init__(self, subvol: Path, target_filter: str, debounce_sec: float):
        self.subvol = subvol
        self.target_filter = target_filter
        self.debounce_sec = debounce_sec
        self.snap_dir = subvol / ".btrfs_monitor_snaps"
        self.snap_count = 0
        self.prev_snap = None
        self.timer = None
        self.lock = threading.Lock()
        self.running = True

    def setup(self):
        self.snap_dir.mkdir(exist_ok=True)
        self._create_initial_snapshot()

    def _create_initial_snapshot(self):
        snap_path = self.snap_dir / f"snap_{self.snap_count}"
        try:
            create_snapshot(self.subvol, snap_path)
            self.prev_snap = snap_path
            self.snap_count += 1
            print(f"[BTRFS] Initial snapshot created: {snap_path.name}")
        except subprocess.CalledProcessError as e:
            print(f"[BTRFS] Failed to create initial snapshot: {e}")

    def trigger(self):
        with self.lock:
            if self.timer:
                self.timer.cancel()
            if self.running:
                self.timer = threading.Timer(self.debounce_sec, self._do_sync)
                self.timer.start()
                print(f"[DEBOUNCE] Timer reset, will sync in {self.debounce_sec}s")

    def _do_sync(self):
        if not self.running:
            return

        print("[BTRFS] Debounce timer expired, starting sync...")
        curr_snap = self.snap_dir / f"snap_{self.snap_count}"

        try:
            create_snapshot(self.subvol, curr_snap)
            print(f"[BTRFS] New snapshot: {curr_snap.name}")
        except subprocess.CalledProcessError as e:
            print(f"[BTRFS] Failed to create snapshot: {e}")
            return

        if self.prev_snap and self.prev_snap.exists():
            try:
                diff_data = get_send_diff(self.prev_snap, curr_snap)
                changes = parse_send_stream(diff_data)

                filtered = [c for c in changes if self._in_target(c.path)]
                if filtered:
                    print(f"[BTRFS] Changes detected ({len(filtered)} items):")
                    for change in filtered:
                        if change.path_to:
                            print(f"  [{change.cmd}] {change.path} -> {change.path_to}")
                        else:
                            print(f"  [{change.cmd}] {change.path}")
                else:
                    print("[BTRFS] No changes in target directory")

            except subprocess.CalledProcessError as e:
                print(f"[BTRFS] Failed to get diff: {e}")

            try:
                delete_snapshot(self.prev_snap)
                print(f"[BTRFS] Deleted old snapshot: {self.prev_snap.name}")
            except Exception:
                pass

        self.prev_snap = curr_snap
        self.snap_count += 1

    def _in_target(self, path: str) -> bool:
        return path.startswith(self.target_filter) or path.startswith(self.target_filter + "/")

    def cleanup(self):
        self.running = False
        with self.lock:
            if self.timer:
                self.timer.cancel()

        if self.prev_snap and self.prev_snap.exists():
            try:
                delete_snapshot(self.prev_snap)
            except Exception:
                pass
        try:
            self.snap_dir.rmdir()
        except Exception:
            pass


def monitor():
    if os.geteuid() != 0:
        print("Error: This script requires root privileges")
        print("Run with: sudo uv run python main.py")
        sys.exit(1)

    check_btrfs()

    target = Path(TARGET_DIR)
    if not target.exists():
        target.mkdir(parents=True)

    target_filter = str(target.relative_to(SUBVOL_PATH))

    print("Fanotify-Btrfs Hybrid Monitor")
    print(f"Monitoring: {TARGET_DIR}")
    print(f"Subvolume: {SUBVOL_PATH}")
    print(f"Debounce: {DEBOUNCE_SECONDS}s")
    print("-" * 50)

    syncer = DebouncedBtrfsSync(SUBVOL_PATH, target_filter, DEBOUNCE_SECONDS)
    syncer.setup()

    init_flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME

    try:
        fd = fanotify_init(init_flags, os.O_RDONLY | os.O_LARGEFILE)
    except OSError as e:
        print(f"fanotify_init failed: {e}")
        syncer.cleanup()
        sys.exit(1)

    mask = (
        FAN_CREATE | FAN_DELETE | FAN_MODIFY | FAN_ATTRIB |
        FAN_MOVED_FROM | FAN_MOVED_TO | FAN_CLOSE_WRITE |
        FAN_ONDIR | FAN_EVENT_ON_CHILD
    )

    try:
        fanotify_mark(fd, FAN_MARK_ADD, mask, AT_FDCWD, TARGET_DIR)
    except OSError as e:
        print(f"fanotify_mark failed: {e}")
        os.close(fd)
        syncer.cleanup()
        sys.exit(1)

    print("[FANOTIFY] Watching for events...")
    print("-" * 50)

    try:
        while True:
            data = os.read(fd, 8192)
            if not data:
                continue

            offset = 0
            while offset < len(data):
                if offset + 24 > len(data):
                    break

                event_len, vers, reserved, metadata_len, mask_val, event_fd, pid = struct.unpack_from(
                    "<IBBHQii", data, offset
                )

                if event_len == 0:
                    break

                if event_fd >= 0:
                    os.close(event_fd)

                print(f"[FANOTIFY] Event detected (mask=0x{mask_val:x}, pid={pid})")
                syncer.trigger()

                offset += event_len

    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        os.close(fd)
        syncer.cleanup()


if __name__ == "__main__":
    monitor()
