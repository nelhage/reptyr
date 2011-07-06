reptyr - A tool for "re-ptying" programs.
-----------------------------------------

reptyr is a utility for taking an existing running program and
attaching it to a new terminal. Started a long-running process over
ssh, but have to leave and don't want to interrupt it? Just start a
screen, use reptyr to grab it, and then kill the ssh session and head
on home.

USAGE
-----

  reptyr PID

"reptyr PID" will grab the process with id PID and attach it to your
current terminal.

After attaching, the process will take input from and write output to
the new terminal, including ^C and ^Z. (Unfortunately, if you
background it, you will still have to run "bg" or "fg" in the old
terminal. This is likely impossible to fix in a reasonable way without
patching your shell.)

"But wait, isn't this just screenify?"
--------------------------------------

There's a shell script called "screenify" that's been going around the
internet for nigh on 10 years now that uses gdb to (supposedly)
accomplish the same thing. The difference is that reptyr works much,
much, better.

If you attach a "less" using screenify, it will still take input from
the old terminal. If you attach an ncurses program using screenify,
and resize the window, your program won't notice. If you attach a
process with screenify, ^C in the new terminal won't work.

reptyr fixes all of these problems, and is the only such tool I know
of that does so. See below for some more details on how it
accomplishes this.

PORTABILITY
-----------

reptyr is Linux-only. It uses ptrace to attach to the target and control it at
the syscall level, so it is highly dependent on Linux's particular syscall API,
syscalls, and terminal ioctl()s. A port to Solaris or BSD may be technically
feasible, but would probably require significant re-architecting to abstract out
the platform-specific bits.

reptyr works on i386, x86_64, and ARM. Ports to other architectures should be
straightforward, and should in most cases be as simple as adding an arch/ARCH.h
file and adding a clause to the ifdef ladder in ptrace.c.

ptrace_scope on Ubuntu Maverick and up
--------------------------------------

`reptyr` depends on the `ptrace` system call to attach to the remote program. On
Ubuntu Maverick and higher, this ability is disabled by default for security
reasons. You can enable it temporarily by doing

 # echo 0 > /proc/sys/kernel/yama/ptrace_scope

as root, or permanently by editing the file /etc/sysctl.d/10-ptrace.conf, which
also contains more information about exactly what this setting accomplishes.

reptyr -l
---------

As a bonus feature, if you run "reptyr -l", reptyr will create a new
pseudo-terminal pair with nothing attached to the slave end, and print
its name out.

If you are debugging a program in gdb, you can pass that name to "set
inferior-pty". Because there is no existing program listening to that
tty, this will work much better than passing an existing shell's
terminal.

How does it work?
-----------------

The main thing that reptyr does that no one else does is that it
actually changes the controlling terminal of the process you are
attaching. I plan on writing up more about just how this works soon,
but for now, the source is only about 1000 lines if you're curious :)

PRONUNCIATION
-------------

I pronounce it like "repeater", but since that's easily ambiguous,
"re-P-T-Y-er" is also acceptable.


CREDITS
-------
reptyr was written by Nelson Elhage <nelhage@nelhage.com>. Contact him
with any questions or bug reports.

URL
---
http://github.com/nelhage/reptyr
