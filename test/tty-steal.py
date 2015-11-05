import prctl
import pexpect
import os
import sys

if os.getenv("NO_TEST_STEAL") is not None:
    print("Skipping tty-stealing tests because $NO_TEST_STEAL is set.")
    sys.exit(0)

PR_SET_PTRACER_ANY = 0xffffffff
prctl.set_ptracer(PR_SET_PTRACER_ANY)

child = pexpect.spawn("test/victim")
child.setecho(False)
child.sendline("hello")
child.expect("ECHO: hello")

reptyr = pexpect.spawn("./reptyr -T %d" % (child.pid,))
reptyr.sendline("world")
reptyr.expect("ECHO: world")

child.sendline("final")
child.expect(pexpect.EOF)
assert os.stat("/dev/null").st_rdev == os.fstat(child.fileno()).st_rdev

reptyr.sendeof()
reptyr.expect(pexpect.EOF)
assert not reptyr.isalive()
