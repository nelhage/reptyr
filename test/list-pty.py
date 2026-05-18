from __future__ import print_function

import subprocess
import sys

cmd = [
    "./reptyr",
    "-L",
    "/bin/sh",
    "-c",
    "printf 'PTY=%s\\n' \"$REPTYR_PTY\"; test -c \"$REPTYR_PTY\"",
]

proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
output, _ = proc.communicate()
if proc.returncode != 0:
    sys.stdout.write(output.decode("utf-8", "replace"))
    raise subprocess.CalledProcessError(proc.returncode, cmd, output)

text = output.decode("utf-8", "replace")
sys.stdout.write(text)

line = next((line for line in text.splitlines() if line.startswith("PTY=")), None)
assert line is not None, "reptyr -L did not print the child pty path"
pty = line[4:]
assert pty.startswith("/dev/"), "unexpected pty path: %r" % (pty,)
