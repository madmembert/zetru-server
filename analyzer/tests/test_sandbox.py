"""Seccomp filter logic is checked with a small BPF interpreter on every platform; the real installation is
exercised only on Linux (skipped elsewhere)."""

import errno
import os
import socket
import sys

import pytest

from zetru_analyzer import sandbox

EPERM = sandbox.SECCOMP_RET_ERRNO | errno.EPERM
ALLOW = sandbox.SECCOMP_RET_ALLOW
KILL = sandbox.SECCOMP_RET_KILL_PROCESS


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_denied_syscalls_return_eperm(arch):
    prog = sandbox.build_filter(arch)
    audit = sandbox.AUDIT_ARCH[arch]
    for name in sandbox.DENY:
        if name in sandbox.SYSCALLS[arch]:
            assert sandbox.run_filter(prog, sandbox.SYSCALLS[arch][name], audit) == EPERM, name


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_open_for_writing_is_denied_reading_allowed(arch):
    prog = sandbox.build_filter(arch)
    audit = sandbox.AUDIT_ARCH[arch]
    nr = sandbox.SYSCALLS[arch]["openat"]
    assert sandbox.run_filter(prog, nr, audit, (0xFFFFFF9C, 0x1000, 0, 0, 0, 0)) == ALLOW            # O_RDONLY
    assert sandbox.run_filter(prog, nr, audit, (0xFFFFFF9C, 0x1000, 0o2000000, 0, 0, 0)) == ALLOW    # O_CLOEXEC
    for flags in (sandbox.O_WRONLY, sandbox.O_RDWR, sandbox.O_CREAT, sandbox.O_TRUNC | sandbox.O_WRONLY,
                  sandbox.O_APPEND, 0o2000000 | sandbox.O_CREAT):
        assert sandbox.run_filter(prog, nr, audit, (0xFFFFFF9C, 0x1000, flags, 0o644, 0, 0)) == EPERM
    if "open" in sandbox.SYSCALLS[arch]:
        nr = sandbox.SYSCALLS[arch]["open"]
        assert sandbox.run_filter(prog, nr, audit, (0x1000, 0, 0, 0, 0, 0)) == ALLOW
        assert sandbox.run_filter(prog, nr, audit, (0x1000, sandbox.O_WRONLY, 0, 0, 0, 0)) == EPERM


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_ordinary_syscalls_allowed(arch):
    prog = sandbox.build_filter(arch)
    audit = sandbox.AUDIT_ARCH[arch]
    ordinary = {"x86_64": [0, 1, 3, 9, 12, 60, 231, 318], "aarch64": [63, 64, 57, 222, 214, 93, 94, 278]}[arch]
    for nr in ordinary:   # read, write, close, mmap, brk, exit, exit_group, getrandom (and aarch64 equivalents)
        assert sandbox.run_filter(prog, nr, audit) == ALLOW


def test_wrong_architecture_is_killed():
    prog = sandbox.build_filter("x86_64")
    assert sandbox.run_filter(prog, 41, sandbox.AUDIT_ARCH_AARCH64) == KILL
    prog = sandbox.build_filter("aarch64")
    assert sandbox.run_filter(prog, 198, sandbox.AUDIT_ARCH_X86_64) == KILL
    assert sandbox.run_filter(prog, 198, 0x40000003) == KILL   # i386


def test_x32_abi_is_killed_on_x86_64():
    prog = sandbox.build_filter("x86_64")
    assert sandbox.run_filter(prog, sandbox.X32_SYSCALL_BIT | 41, sandbox.AUDIT_ARCH_X86_64) == KILL
    assert sandbox.run_filter(prog, sandbox.X32_SYSCALL_BIT | 0, sandbox.AUDIT_ARCH_X86_64) == KILL


def test_numbers_do_not_collide_with_allowed_basics():
    # aarch64 'connect' (203) is sched_setaffinity on x86_64 and must stay allowed there.
    prog = sandbox.build_filter("x86_64")
    assert sandbox.run_filter(prog, 203, sandbox.AUDIT_ARCH_X86_64) == ALLOW
    for arch in ("x86_64", "aarch64"):
        assert len(sandbox.build_filter(arch)) < 255


def test_non_linux_skips_with_warning(capsys):
    if sys.platform.startswith("linux"):
        pytest.skip("Linux runs the real sandbox test below")
    assert sandbox.harden_worker(enforce=True) is False
    assert "sandbox_skipped" in capsys.readouterr().err


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="seccomp exists only on Linux")
def test_real_sandbox_in_forked_child(tmp_path):
    read_path = tmp_path / "readable.txt"
    read_path.write_text("ok")
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        w = sandbox.close_inherited_fds(w)   # as the worker does: only stdio and its channel stay open
        results = []
        try:
            sandbox.harden_worker(enforce=True)
            results.append("hardened")
            for action in (
                lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                lambda: open(tmp_path / "new.txt", "w"),
                lambda: os.execv("/bin/true", ["true"]),
                lambda: os.fork(),
                lambda: os.kill(os.getppid(), 0),          # PY-08: no signals to the zygote or supervisor
                lambda: os.mkdir(tmp_path / "dir"),          # PY-08: nothing left behind for later workers
                lambda: os.symlink("x", tmp_path / "link"),
                lambda: os.unlink(read_path),
                lambda: os.memfd_create("x"),
            ):
                try:
                    action()
                    results.append("allowed")
                except OSError:
                    results.append("denied")
            with open(read_path) as handle:
                results.append(handle.read())
        except BaseException as exc:  # noqa: BLE001
            results.append(type(exc).__name__)
        os.write(w, ",".join(results).encode())
        os._exit(0)
    os.close(w)
    data = os.read(r, 1000).decode()
    os.waitpid(pid, 0)
    assert data == "hardened," + ",".join(["denied"] * 9) + ",ok"
