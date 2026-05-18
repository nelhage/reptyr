#!/usr/bin/env python3
import os
import pty
import select
import signal
import subprocess
import sys
import time


PROCS = []


class ForkedProc:
    def __init__(self, pid):
        self.pid = pid
        self.returncode = None

    def poll(self):
        if self.returncode is not None:
            return self.returncode
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.returncode = 0
            return self.returncode
        if pid == 0:
            return None
        if os.WIFEXITED(status):
            self.returncode = os.WEXITSTATUS(status)
        elif os.WIFSIGNALED(status):
            self.returncode = -os.WTERMSIG(status)
        else:
            self.returncode = status
        return self.returncode

    def terminate(self):
        if self.poll() is None:
            os.kill(self.pid, signal.SIGTERM)

    def kill(self):
        if self.poll() is None:
            os.kill(self.pid, signal.SIGKILL)

    def wait(self, timeout=None):
        deadline = None if timeout is None else time.time() + timeout
        while self.poll() is None:
            if deadline is not None and time.time() > deadline:
                raise subprocess.TimeoutExpired(["pid", str(self.pid)], timeout or 0)
            time.sleep(0.05)
        return self.returncode


def codesign_for_task_for_pid(*paths):
    entitlements = "test/darwin-debug.entitlements"
    for path in paths:
        subprocess.check_call([
            "codesign",
            "-s",
            "-",
            "--force",
            "--entitlements",
            entitlements,
            path,
        ])


def read_until(fd, needle, timeout=5):
    deadline = time.time() + timeout
    data = b""
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.1)
        if fd not in r:
            continue
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        data += chunk
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        if needle in data:
            return data
    raise AssertionError("timed out waiting for %r; got %r" % (needle, data))


def spawn_on_controlling_pty(argv, env=None):
    pid, master = pty.fork()
    if pid == 0:
        if env:
            os.environ.update(env)
        os.execvp(argv[0], argv)
    proc = ForkedProc(pid)
    PROCS.append(proc)
    return proc, master


def stop_process(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def exercise_attach(reptyr_args, initial_word, attached_word, child_env=None):
    child, child_fd = spawn_on_controlling_pty(["test/darwin-victim"], child_env)
    try:
        if initial_word is not None:
            os.write(child_fd, (initial_word + "\n").encode("ascii"))
            read_until(child_fd, ("ECHO: " + initial_word).encode("ascii"))
        else:
            read_until(child_fd, b"READY")

        reptyr, reptyr_fd = spawn_on_controlling_pty(["./reptyr", "-V"] + reptyr_args + [str(child.pid)])
        read_until(reptyr_fd, b"Darwin fd redirect payload completed")
        os.write(reptyr_fd, (attached_word + "\n").encode("ascii"))
        read_until(reptyr_fd, ("ECHO: " + attached_word).encode("ascii"))
        stop_process(reptyr)
    finally:
        stop_process(child)


try:
    codesign_for_task_for_pid("./reptyr", "test/darwin-victim")
    exercise_attach(["-s"], "hello", "world")
    exercise_attach(["-s"], None, "restored", {"DARWIN_VICTIM_CLOSE_STDIN": "1"})
    exercise_attach([], "plain", "attach")
finally:
    for proc in reversed(PROCS):
        stop_process(proc)
