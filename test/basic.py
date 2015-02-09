import pexpect

child = pexpect.spawn("test/victim")
child.setecho(False)
child.sendline("hello")
child.expect("ECHO: hello")

reptyr = pexpect.spawn("./reptyr %d" % (child.pid,))
reptyr.sendline("world")
reptyr.expect("ECHO: world")

child.sendline("final")
child.expect(pexpect.EOF)

reptyr.sendeof()
reptyr.expect(pexpect.EOF)
assert not reptyr.isalive()
