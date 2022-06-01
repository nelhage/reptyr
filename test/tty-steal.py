import pexpect
import os
import sys

from util import expect_eof

if os.getenv("NO_TEST_STEAL") is not None:
    print("Skipping tty-stealing tests because $NO_TEST_STEAL is set.")
    sys.exit(0)

logfile = sys.stdout
if sys.version_info[0] >= 3:
    logfile = logfile.buffer

did_prctl = False
try:
    import prctl
    PR_SET_PTRACER_ANY = 0xffffffff
    if hasattr(prctl, 'set_ptracer'):
        did_prctl = True
        prctl.set_ptracer(PR_SET_PTRACER_ANY)
except ImportError:
    pass

if not did_prctl:
  print("Unable to find `prctl.set_ptracer`, skipping `PR_SET_PTRACER`.")

child = pexpect.spawn("test/victim")
child.setecho(False)
child.sendline("hello")
child.expect("ECHO: hello")

reptyr = pexpect.spawn("./reptyr -V -T %d" % (child.pid,))
print("spawned children: me={} victim={} reptyr={}".format(os.getpid(), child.pid, reptyr.pid))
reptyr.logfile = logfile

reptyr.sendline("world")
reptyr.expect("ECHO: world")

child.sendline("final")
expect_eof(child.child_fd)
assert os.stat("/dev/null").st_rdev == os.fstat(child.fileno()).st_rdev

reptyr.sendeof()
reptyr.expect(pexpect.EOF)
assert not reptyr.isalive()
