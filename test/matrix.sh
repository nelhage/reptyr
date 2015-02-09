#!/bin/sh

echo "64-bit..."
make clean
make CFLAGS=-m64 LDFLAGS=-m64 test

echo "32-bit..."
make clean
env NO_TEST_STEAL=1 make CFLAGS=-m32 LDFLAGS=-m32 test

echo "32-on-64..."
make clean
make VICTIM_CFLAGS=-m32 VICTIM_LDFLAGS=-m32 test
