import os
import pexpect
import sys

from util import expect_eof

if os.getenv("NO_TEST_BASIC") is not None:
    print("Skipping basic tests because $NO_TEST_BASIC is set.")
    sys.exit(0)

logfile = sys.stdout
if sys.version_info[0] >= 3:
    logfile = logfile.buffer

child = pexpect.spawn("test/victim")
child.logfile = logfile
child.setecho(False)
child.sendline("hello")
child.expect("ECHO: hello\r\n")

reptyr = pexpect.spawn("./reptyr -V %d" % (child.pid,))
reptyr.logfile = logfile
reptyr.sendline("world")
reptyr.expect("ECHO: world\r\n")

child.sendline("final")
expect_eof(child.child_fd)

reptyr.sendeof()
reptyr.expect(pexpect.EOF)
assert not reptyr.isalive()
