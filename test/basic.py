import pexpect
import sys

from util import expect_eof

logfile = sys.stdout
if sys.version_info[0] >= 3:
    logfile = logfile.buffer

child = pexpect.spawn("test/victim")
child.logfile = logfile
child.setecho(False)
child.sendline("hello")
child.expect("ECHO: hello")

reptyr = pexpect.spawn("./reptyr -V %d" % (child.pid,))
reptyr.logfile = logfile
reptyr.sendline("world")
reptyr.expect("ECHO: world")

child.sendline("final")
expect_eof(child.child_fd)

reptyr.sendeof()
reptyr.expect(pexpect.EOF)
assert not reptyr.isalive()
