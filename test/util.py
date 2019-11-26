import os
import errno
import select

def expect_eof(fd):
  r, _, _ = select.select([fd], [], [])
  if fd not in r:
    raise AssertionError("Expected EOF, fd not readable")
  try:
    data = os.read(fd, 1024)
    if len(data) == 0:
      return
    raise AssertionError("Expected EOF, got read: `{}'".format(data))
  except OSError as e:
    if e.errno == errno.EIO:
      return
    raise AssertionError("Expected EOF, other expection: {}".format(e))
