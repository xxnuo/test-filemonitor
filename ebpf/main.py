#!/usr/bin/env python3
import os
import sys
import ctypes
from pathlib import Path

TARGET_DIR = "/home/xxnuo/projects/test-filemonitor/target"

try:
    from bcc import BPF
except ImportError:
    print("Error: bcc not found. Install with:")
    print("  Arch: sudo pacman -S bcc bcc-tools python-bcc")
    print("  Ubuntu: sudo apt install bpfcc-tools python3-bpfcc")
    sys.exit(1)

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/dcache.h>

#define MAX_PATH_LEN 256

enum event_type {
    EVENT_OPEN = 1,
    EVENT_CREATE,
    EVENT_UNLINK,
    EVENT_RENAME,
    EVENT_WRITE,
    EVENT_MKDIR,
    EVENT_RMDIR,
};

struct event_t {
    u32 pid;
    u32 uid;
    u64 ts;
    u32 event_type;
    char comm[TASK_COMM_LEN];
    char filename[MAX_PATH_LEN];
    char filename2[MAX_PATH_LEN];
};

BPF_PERF_OUTPUT(events);

static __always_inline bool str_startswith(const char *str, const char *prefix, int prefix_len) {
    #pragma unroll
    for (int i = 0; i < prefix_len && i < MAX_PATH_LEN; i++) {
        char c1 = 0, c2 = 0;
        bpf_probe_read_kernel(&c1, 1, str + i);
        c2 = prefix[i];
        if (c1 != c2) return false;
        if (c2 == 0) return true;
    }
    return true;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.ts = bpf_ktime_get_ns();
    event.event_type = EVENT_OPEN;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    int flags = args->flags;
    if (flags & 0x40) {
        event.event_type = EVENT_CREATE;
    }

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.ts = bpf_ktime_get_ns();

    int flags = args->flag;
    if (flags & 0x200) {
        event.event_type = EVENT_RMDIR;
    } else {
        event.event_type = EVENT_UNLINK;
    }

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->pathname);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.ts = bpf_ktime_get_ns();
    event.event_type = EVENT_RENAME;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->oldname);
    bpf_probe_read_user_str(&event.filename2, sizeof(event.filename2), args->newname);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.ts = bpf_ktime_get_ns();
    event.event_type = EVENT_RENAME;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->oldname);
    bpf_probe_read_user_str(&event.filename2, sizeof(event.filename2), args->newname);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_mkdirat) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.ts = bpf_ktime_get_ns();
    event.event_type = EVENT_MKDIR;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->pathname);

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.ts = bpf_ktime_get_ns();
    event.event_type = EVENT_WRITE;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.filename[0] = 0;

    events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

EVENT_OPEN = 1
EVENT_CREATE = 2
EVENT_UNLINK = 3
EVENT_RENAME = 4
EVENT_WRITE = 5
EVENT_MKDIR = 6
EVENT_RMDIR = 7

EVENT_NAMES = {
    EVENT_OPEN: "OPEN",
    EVENT_CREATE: "CREATE",
    EVENT_UNLINK: "DELETE",
    EVENT_RENAME: "RENAME",
    EVENT_WRITE: "WRITE",
    EVENT_MKDIR: "MKDIR",
    EVENT_RMDIR: "RMDIR",
}

class Event(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("ts", ctypes.c_uint64),
        ("event_type", ctypes.c_uint32),
        ("comm", ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
        ("filename2", ctypes.c_char * 256),
    ]

def is_target_path(path: str) -> bool:
    if not path:
        return False
    abs_path = os.path.abspath(path) if not path.startswith('/') else path
    return abs_path.startswith(TARGET_DIR) or TARGET_DIR in path

def monitor():
    if os.geteuid() != 0:
        print("Error: This script requires root privileges")
        print("Run with: sudo uv run python monitor.py")
        sys.exit(1)

    target = Path(TARGET_DIR)
    if not target.exists():
        target.mkdir(parents=True)

    print("eBPF Monitor started")
    print(f"Monitoring: {TARGET_DIR}")
    print("-" * 50)

    try:
        b = BPF(text=BPF_PROGRAM)
    except Exception as e:
        print(f"Failed to load BPF program: {e}")
        sys.exit(1)

    def handle_event(cpu, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Event)).contents

        filename = event.filename.decode('utf-8', errors='replace').rstrip('\x00')
        filename2 = event.filename2.decode('utf-8', errors='replace').rstrip('\x00')
        comm = event.comm.decode('utf-8', errors='replace').rstrip('\x00')

        if event.event_type == EVENT_WRITE:
            return

        if not is_target_path(filename) and not is_target_path(filename2):
            return

        event_name = EVENT_NAMES.get(event.event_type, f"UNKNOWN({event.event_type})")

        if event.event_type == EVENT_RENAME and filename2:
            print(f"[{event_name}] {filename} -> {filename2} (pid={event.pid}, comm={comm})")
        else:
            print(f"[{event_name}] {filename} (pid={event.pid}, comm={comm})")

    b["events"].open_perf_buffer(handle_event)

    print("Waiting for events...")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        print("\nStopping...")

if __name__ == "__main__":
    monitor()
