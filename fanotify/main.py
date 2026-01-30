#!/usr/bin/env python3
import os
import sys
import struct
import ctypes
import ctypes.util
from pathlib import Path

TARGET_DIR = "/home/xxnuo/projects/test-filemonitor/target"

FAN_CLASS_NOTIF = 0x00000000
FAN_CLASS_CONTENT = 0x00000004
FAN_CLASS_PRE_CONTENT = 0x00000008
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_UNLIMITED_MARKS = 0x00000020
FAN_REPORT_FID = 0x00000200
FAN_REPORT_DIR_FID = 0x00000400
FAN_REPORT_NAME = 0x00000800

FAN_MARK_ADD = 0x00000001
FAN_MARK_REMOVE = 0x00000002
FAN_MARK_FLUSH = 0x00000080
FAN_MARK_FILESYSTEM = 0x00000100

FAN_ACCESS = 0x00000001
FAN_MODIFY = 0x00000002
FAN_ATTRIB = 0x00000004
FAN_CLOSE_WRITE = 0x00000008
FAN_CLOSE_NOWRITE = 0x00000010
FAN_OPEN = 0x00000020
FAN_MOVED_FROM = 0x00000040
FAN_MOVED_TO = 0x00000080
FAN_CREATE = 0x00000100
FAN_DELETE = 0x00000200
FAN_DELETE_SELF = 0x00000400
FAN_MOVE_SELF = 0x00000800
FAN_OPEN_EXEC = 0x00001000
FAN_ONDIR = 0x40000000
FAN_EVENT_ON_CHILD = 0x08000000

AT_FDCWD = -100

EVENT_NAMES = {
    FAN_ACCESS: "ACCESS",
    FAN_MODIFY: "MODIFY",
    FAN_ATTRIB: "ATTRIB",
    FAN_CLOSE_WRITE: "CLOSE_WRITE",
    FAN_CLOSE_NOWRITE: "CLOSE_NOWRITE",
    FAN_OPEN: "OPEN",
    FAN_MOVED_FROM: "MOVED_FROM",
    FAN_MOVED_TO: "MOVED_TO",
    FAN_CREATE: "CREATE",
    FAN_DELETE: "DELETE",
    FAN_DELETE_SELF: "DELETE_SELF",
    FAN_MOVE_SELF: "MOVE_SELF",
    FAN_OPEN_EXEC: "OPEN_EXEC",
}

class fanotify_event_metadata(ctypes.Structure):
    _fields_ = [
        ("event_len", ctypes.c_uint32),
        ("vers", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask", ctypes.c_uint64),
        ("fd", ctypes.c_int32),
        ("pid", ctypes.c_int32),
    ]

class file_handle(ctypes.Structure):
    _fields_ = [
        ("handle_bytes", ctypes.c_uint),
        ("handle_type", ctypes.c_int),
    ]

class fanotify_event_info_header(ctypes.Structure):
    _fields_ = [
        ("info_type", ctypes.c_uint8),
        ("pad", ctypes.c_uint8),
        ("len", ctypes.c_uint16),
    ]

FAN_EVENT_INFO_TYPE_FID = 1
FAN_EVENT_INFO_TYPE_DFID_NAME = 2
FAN_EVENT_INFO_TYPE_DFID = 3

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

def get_event_names(mask):
    names = []
    for flag, name in EVENT_NAMES.items():
        if mask & flag:
            names.append(name)
    if mask & FAN_ONDIR:
        names.append("(DIR)")
    return names

def get_path_from_fd(fd):
    try:
        return os.readlink(f"/proc/self/fd/{fd}")
    except:
        return "<unknown>"

def parse_fid_event(data, offset, event_len):
    if offset + 4 > len(data):
        return None, None

    info_type, pad, info_len = struct.unpack_from("<BBH", data, offset)

    if info_type not in (FAN_EVENT_INFO_TYPE_FID, FAN_EVENT_INFO_TYPE_DFID_NAME, FAN_EVENT_INFO_TYPE_DFID):
        return None, None

    if offset + 8 + 8 > len(data):
        return None, None

    fsid = struct.unpack_from("<Q", data, offset + 4)[0]
    handle_bytes, handle_type = struct.unpack_from("<IB", data, offset + 12)

    filename = None
    if info_type == FAN_EVENT_INFO_TYPE_DFID_NAME:
        name_offset = offset + 12 + 4 + 1 + 3 + handle_bytes
        if name_offset < len(data):
            name_end = data.find(b'\x00', name_offset)
            if name_end > name_offset:
                filename = data[name_offset:name_end].decode('utf-8', errors='replace')

    return fsid, filename

def monitor():
    if os.geteuid() != 0:
        print("Error: This script requires root privileges")
        print("Run with: sudo uv run python monitor.py")
        sys.exit(1)

    target = Path(TARGET_DIR)
    if not target.exists():
        target.mkdir(parents=True)

    print("Fanotify Monitor started")
    print(f"Monitoring: {TARGET_DIR}")
    print("-" * 50)

    init_flags = FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_REPORT_FID | FAN_REPORT_DIR_FID | FAN_REPORT_NAME

    try:
        fd = fanotify_init(init_flags, os.O_RDONLY | os.O_LARGEFILE)
    except OSError as e:
        print(f"fanotify_init failed: {e}")
        if e.errno == 1:
            print("Need CAP_SYS_ADMIN capability")
        sys.exit(1)

    mask = (
        FAN_CREATE | FAN_DELETE | FAN_MODIFY | FAN_ATTRIB |
        FAN_MOVED_FROM | FAN_MOVED_TO |
        FAN_ONDIR | FAN_EVENT_ON_CHILD
    )

    try:
        fanotify_mark(fd, FAN_MARK_ADD, mask, AT_FDCWD, TARGET_DIR)
    except OSError as e:
        print(f"fanotify_mark failed: {e}")
        os.close(fd)
        sys.exit(1)

    print("Waiting for events...")

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

                events = get_event_names(mask_val)
                event_str = "|".join(events)

                filename = None
                if metadata_len < event_len:
                    _, filename = parse_fid_event(data, offset + metadata_len, event_len)

                if event_fd >= 0:
                    path = get_path_from_fd(event_fd)
                    os.close(event_fd)
                    print(f"[{event_str}] {path} (pid={pid})")
                elif filename:
                    print(f"[{event_str}] {TARGET_DIR}/{filename} (pid={pid})")
                else:
                    print(f"[{event_str}] <unknown> (pid={pid})")

                offset += event_len

    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        os.close(fd)

if __name__ == "__main__":
    monitor()
