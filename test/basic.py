import pexpect
import sys

child = pexpect.spawn("test/victim")
child.logfile = sys.stdout
child.setecho(False)
child.sendline("hello")
child.expect("ECHO: hello")

reptyr = pexpect.spawn("./reptyr -V %d" % (child.pid,))
reptyr.logfile = sys.stdout
reptyr.sendline("world")
reptyr.expect("ECHO: world")

child.sendline("final")
child.expect(pexpect.EOF)

reptyr.sendeof()
reptyr.expect(pexpect.EOF)
assert not reptyr.isalive()
