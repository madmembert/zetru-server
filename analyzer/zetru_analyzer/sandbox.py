"""Worker hardening (concept §3.2): rlimits, PR_SET_NO_NEW_PRIVS, PR_SET_DUMPABLE 0 and a seccomp-BPF
filter installed with prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER) through ctypes.

The filter first checks the architecture (x86_64 or aarch64; anything else kills the process), rejects the
x32 ABI on x86_64, and returns EPERM for everything in DENY and for open/openat with any of O_WRONLY, O_RDWR,
O_CREAT, O_TRUNC, O_APPEND. Everything else is allowed. DENY covers
- network and process creation: socket, socketpair, connect, bind, listen, accept, accept4, execve, execveat,
  clone, clone3, fork, vfork, unshare, setns;
- other processes: ptrace, process_vm_readv/writev, kcmp, pidfd_open, pidfd_getfd, and every way to send a
  signal (kill, tkill, tgkill, rt_sigqueueinfo, rt_tgsigqueueinfo, pidfd_send_signal) — a compromised worker
  cannot stop the zygote or the supervisor (security review PY-08);
- the file system beyond reading: creat, openat2 (its flags live in a struct the filter cannot inspect),
  mkdir(at), mknod(at), link(at), symlink(at), unlink(at), rmdir, rename(at/at2), truncate, ftruncate, chmod
  family, chown family, xattr writes, utime family, name_to_handle_at, open_by_handle_at — nothing a worker
  leaves behind can reach a later worker;
- kernel objects that outlive the worker or widen the attack surface: SysV and POSIX message queues,
  semaphores and shared memory, keyctl/add_key/request_key, memfd_create, bpf, userfaultfd, perf_event_open,
  io_uring_setup/enter/register (io_uring would bypass per-syscall filtering), mount, umount2 and the new mount
  API;
- prctl, so neither PR_SET_DUMPABLE nor PR_SET_PDEATHSIG can be undone after the filter is installed.

`set_not_dumpable()` is also called by the supervisor and the zygote (PY-07): non-dumpable processes have their
/proc/<pid> files owned by root, so a compromised worker running as the same uid cannot open the supervisor's
/proc/1/mem (with kernel.yama.ptrace_scope 0 it otherwise could).

On anything other than Linux the sandbox is skipped with a logged warning (local development on macOS).
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import resource
import struct
import sys

from . import logs

# Limits (concept §3.2).
RLIMIT_AS_BYTES = 768 * 1024 * 1024
RLIMIT_CPU_S = 10
RLIMIT_NOFILE_N = 32

# BPF opcodes.
BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_JMP_JGE_K = 0x35
BPF_JMP_JSET_K = 0x45
BPF_RET_K = 0x06

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7
X32_SYSCALL_BIT = 0x40000000

PR_SET_DUMPABLE = 4
PR_SET_PDEATHSIG = 1
PR_SET_SECCOMP = 22
PR_SET_NO_NEW_PRIVS = 38
SECCOMP_MODE_FILTER = 2

# open(2) flag bits that imply writing or creating (identical on x86_64 and aarch64, asm-generic values).
O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND = 0o1, 0o2, 0o100, 0o1000, 0o2000
WRITE_FLAGS = O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND

# Syscall numbers (x86_64: arch/x86/entry/syscalls/syscall_64.tbl; aarch64: include/uapi/asm-generic/unistd.h).
# Numbers ≥ 424 are shared by all architectures.
COMMON_NEW = {"pidfd_send_signal": 424, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
              "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433,
              "pidfd_open": 434, "clone3": 435, "openat2": 437, "pidfd_getfd": 438, "mount_setattr": 442,
              "fchmodat2": 452}
SYSCALLS = {
    "x86_64": {
        "open": 2, "shmget": 29, "shmat": 30, "shmctl": 31, "socket": 41, "connect": 42, "accept": 43, "bind": 49,
        "listen": 50, "socketpair": 53, "clone": 56, "fork": 57, "vfork": 58, "execve": 59, "kill": 62,
        "semget": 64, "semop": 65, "semctl": 66, "shmdt": 67, "msgget": 68, "msgsnd": 69, "msgrcv": 70, "msgctl": 71,
        "truncate": 76, "ftruncate": 77, "rename": 82, "mkdir": 83, "rmdir": 84, "creat": 85, "link": 86,
        "unlink": 87, "symlink": 88, "chmod": 90, "fchmod": 91, "chown": 92, "fchown": 93, "lchown": 94,
        "ptrace": 101, "rt_sigqueueinfo": 129, "utime": 132, "mknod": 133, "prctl": 157, "mount": 165,
        "umount2": 166, "setxattr": 188, "lsetxattr": 189, "fsetxattr": 190, "removexattr": 197,
        "lremovexattr": 198, "fremovexattr": 199, "tkill": 200, "semtimedop": 220, "tgkill": 234, "utimes": 235,
        "mq_open": 240, "mq_unlink": 241, "add_key": 248, "request_key": 249, "keyctl": 250, "openat": 257,
        "mkdirat": 258, "mknodat": 259, "fchownat": 260, "futimesat": 261, "unlinkat": 263, "renameat": 264,
        "linkat": 265, "symlinkat": 266, "fchmodat": 268, "unshare": 272, "utimensat": 280, "accept4": 288,
        "rt_tgsigqueueinfo": 297, "perf_event_open": 298, "name_to_handle_at": 303, "open_by_handle_at": 304,
        "setns": 308, "process_vm_readv": 310, "process_vm_writev": 311, "kcmp": 312, "renameat2": 316,
        "memfd_create": 319, "bpf": 321, "execveat": 322, "userfaultfd": 323, **COMMON_NEW,
    },
    "aarch64": {
        "setxattr": 5, "lsetxattr": 6, "fsetxattr": 7, "removexattr": 14, "lremovexattr": 15, "fremovexattr": 16,
        "mknodat": 33, "mkdirat": 34, "unlinkat": 35, "symlinkat": 36, "linkat": 37, "renameat": 38,
        "umount2": 39, "mount": 40, "truncate": 45, "ftruncate": 46, "fchmod": 52, "fchmodat": 53,
        "fchownat": 54, "fchown": 55, "openat": 56, "utimensat": 88, "unshare": 97, "ptrace": 117, "kill": 129,
        "tkill": 130, "tgkill": 131, "rt_sigqueueinfo": 138, "prctl": 167, "mq_open": 180, "mq_unlink": 181,
        "msgget": 186, "msgctl": 187, "msgrcv": 188, "msgsnd": 189, "semget": 190, "semctl": 191,
        "semtimedop": 192, "semop": 193, "shmget": 194, "shmctl": 195, "shmat": 196, "shmdt": 197, "socket": 198,
        "socketpair": 199, "bind": 200, "listen": 201, "accept": 202, "connect": 203, "add_key": 217,
        "request_key": 218, "keyctl": 219, "clone": 220, "execve": 221, "rt_tgsigqueueinfo": 240,
        "perf_event_open": 241, "accept4": 242, "name_to_handle_at": 264, "open_by_handle_at": 265, "setns": 268,
        "process_vm_readv": 270, "process_vm_writev": 271, "kcmp": 272, "renameat2": 276, "memfd_create": 279,
        "bpf": 280, "execveat": 281, "userfaultfd": 282, **COMMON_NEW,
    },
}
DENY = (
    # network and process creation
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4", "execve", "execveat", "clone",
    "clone3", "fork", "vfork", "unshare", "setns",
    # other processes and signals
    "ptrace", "process_vm_readv", "process_vm_writev", "kcmp", "pidfd_open", "pidfd_getfd", "kill", "tkill",
    "tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo", "pidfd_send_signal",
    # file system changes
    "creat", "openat2", "mkdir", "mkdirat", "mknod", "mknodat", "link", "linkat", "symlink", "symlinkat", "unlink",
    "unlinkat", "rmdir", "rename", "renameat", "renameat2", "truncate", "ftruncate", "chmod", "fchmod", "fchmodat",
    "fchmodat2", "chown", "fchown", "lchown", "fchownat", "setxattr", "lsetxattr", "fsetxattr", "removexattr",
    "lremovexattr", "fremovexattr", "utime", "utimes", "futimesat", "utimensat", "name_to_handle_at",
    "open_by_handle_at",
    # persistent or kernel-level objects
    "shmget", "shmat", "shmctl", "shmdt", "semget", "semop", "semctl", "semtimedop", "msgget", "msgsnd", "msgrcv",
    "msgctl", "mq_open", "mq_unlink", "add_key", "request_key", "keyctl", "memfd_create", "bpf", "userfaultfd",
    "perf_event_open", "io_uring_setup", "io_uring_enter", "io_uring_register", "mount", "umount2", "open_tree",
    "move_mount", "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr",
    # the process's own hardening
    "prctl",
)
AUDIT_ARCH = {"x86_64": AUDIT_ARCH_X86_64, "aarch64": AUDIT_ARCH_AARCH64}

# Offsets in struct seccomp_data {int nr; u32 arch; u64 ip; u64 args[6];} (little-endian: low word first).
OFF_NR, OFF_ARCH = 0, 4


def _arg_low(index: int) -> int:
    return 16 + 8 * index


def _stmt(code: int, k: int) -> tuple:
    return (code, 0, 0, k)


def _jump(code: int, k: int, jt: int, jf: int) -> tuple:
    return (code, jt, jf, k)


def build_filter(arch: str) -> list[tuple]:
    """Returns the BPF program as (code, jt, jf, k) tuples. Every denied number jumps to one shared EPERM
    return at the end, so the program stays well below the 255-instruction jump range."""
    nums = SYSCALLS[arch]
    eperm = SECCOMP_RET_ERRNO | errno.EPERM
    prog: list[tuple] = [
        _stmt(BPF_LD_W_ABS, OFF_ARCH),
        _jump(BPF_JMP_JEQ_K, AUDIT_ARCH[arch], 1, 0),
        _stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        _stmt(BPF_LD_W_ABS, OFF_NR),
    ]
    if arch == "x86_64":
        prog += [_jump(BPF_JMP_JGE_K, X32_SYSCALL_BIT, 0, 1), _stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS)]
    # open(path, flags) has flags in args[1]; openat(dirfd, path, flags) in args[2].
    for name, arg in (("open", 1), ("openat", 2)):
        if name not in nums:
            continue
        prog += [
            _jump(BPF_JMP_JEQ_K, nums[name], 0, 4),
            _stmt(BPF_LD_W_ABS, _arg_low(arg)),
            _jump(BPF_JMP_JSET_K, WRITE_FLAGS, 0, 1),
            _stmt(BPF_RET_K, eperm),
            _stmt(BPF_LD_W_ABS, OFF_NR),   # restore nr for the following comparisons
        ]
    denied = sorted({nums[name] for name in DENY if name in nums})
    for index, nr in enumerate(denied):
        # jt skips the remaining comparisons and the ALLOW return and lands on the shared EPERM return.
        prog.append(_jump(BPF_JMP_JEQ_K, nr, len(denied) - index, 0))
    prog.append(_stmt(BPF_RET_K, SECCOMP_RET_ALLOW))
    prog.append(_stmt(BPF_RET_K, eperm))
    return prog


def run_filter(prog: list[tuple], nr: int, arch: int, args: tuple = (0, 0, 0, 0, 0, 0)) -> int:
    """Minimal classic-BPF interpreter for the instructions used above (tests run it on any platform)."""
    data = struct.pack("<iIQ6Q", nr, arch, 0, *args)
    acc = 0
    pc = 0
    while pc < len(prog):
        code, jt, jf, k = prog[pc]
        if code == BPF_LD_W_ABS:
            acc = struct.unpack_from("<I", data, k)[0]
            pc += 1
        elif code == BPF_RET_K:
            return k
        elif code in (BPF_JMP_JEQ_K, BPF_JMP_JGE_K, BPF_JMP_JSET_K):
            if code == BPF_JMP_JEQ_K:
                cond = acc == k
            elif code == BPF_JMP_JGE_K:
                cond = acc >= k
            else:
                cond = bool(acc & k)
            pc += 1 + (jt if cond else jf)
        else:
            raise ValueError("unsupported instruction")
    raise ValueError("program fell through")


def machine_arch() -> str | None:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "aarch64"
    return None


class SandboxError(Exception):
    pass


def _libc():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    return libc


def _prctl(libc, option: int, arg2: int = 0) -> None:
    if libc.prctl(option, arg2, 0, 0, 0) != 0:
        raise SandboxError(f"prctl({option}) failed: errno {ctypes.get_errno()}")


def install_seccomp(arch: str) -> None:
    prog = build_filter(arch)

    class SockFilter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8), ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]

    for code, jt, jf, _ in prog:
        if jt > 255 or jf > 255:
            raise SandboxError("jump out of range")
    filters = (SockFilter * len(prog))(*[SockFilter(c, jt, jf, k) for c, jt, jf, k in prog])
    fprog = SockFprog(len(prog), ctypes.cast(filters, ctypes.POINTER(SockFilter)))
    libc = _libc()
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(fprog), 0, 0) != 0:
        raise SandboxError(f"seccomp failed: errno {ctypes.get_errno()}")


def apply_rlimits() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (RLIMIT_AS_BYTES, RLIMIT_AS_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (RLIMIT_CPU_S, RLIMIT_CPU_S + 1))
    resource.setrlimit(resource.RLIMIT_NOFILE, (RLIMIT_NOFILE_N, RLIMIT_NOFILE_N))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))


def set_not_dumpable() -> bool:
    """PR_SET_DUMPABLE 0 for the calling process (supervisor and zygote; the worker does it in harden_worker).
    Returns True when it took effect; outside Linux it does nothing."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        _prctl(_libc(), PR_SET_DUMPABLE, 0)
        return True
    except (SandboxError, OSError, AttributeError):
        return False


def harden_worker(enforce: bool = True) -> bool:
    """Applies all restrictions. Returns True when the full sandbox is active. On Linux any failure raises
    (the worker must not run unsandboxed) unless `enforce` is False."""
    if not sys.platform.startswith("linux"):
        logs.warning("sandbox_skipped", reason="not_linux")
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except (ValueError, OSError):
            pass
        return False
    try:
        libc = _libc()
        _prctl(libc, PR_SET_PDEATHSIG, 9)
        _prctl(libc, PR_SET_DUMPABLE, 0)
        apply_rlimits()
        _prctl(libc, PR_SET_NO_NEW_PRIVS, 1)
        arch = machine_arch()
        if arch is None:
            raise SandboxError("unsupported architecture")
        install_seccomp(arch)
        return True
    except (SandboxError, OSError, ValueError) as exc:
        if enforce:
            raise SandboxError(str(exc)) from None
        logs.warning("sandbox_partial", reason="not_enforced")
        return False


def close_inherited_fds(keep: int) -> int:
    """Moves `keep` to fd 3 and closes every other descriptor above stderr. Returns the new fd."""
    if keep != 3:
        os.dup2(keep, 3)
        os.close(keep)
    os.closerange(4, 65536)
    return 3
