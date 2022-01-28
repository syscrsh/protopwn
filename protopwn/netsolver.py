import protopwn as p
import socket
import struct
import re
import warnings
import time

def recv(con, b):
    while True:
        try:
            data = con.recv(b)
        except socket.timeout, e:
            err = e.args[0]
            if err == 'timed out':
                time.sleep(1)
                p.warn("recv() timed out, trying again")
                continue
            else:
                p.err(e)
        except socket.error, e:
            p.err(e)
        else:
            if len(data) == 0:
                p.warn("server seems busy")
                exit(1)
            else:
                return data

#----------------------------------+
# send a randomly generated number |
# back in little endian format     |
#----------------------------------+
def net0():
    p.start("net0")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 2999))
        s.settimeout(1)
    except:
        p.err("failed to setup socket")

    data = recv(s, 64)

    random_num = re.findall(r"'([0-9]+)'", data)
    random_num = int(random_num[0])

    num = struct.pack("<I", random_num)

    s.sendall(num)
    resp = recv(s, 64)
    s.close()

    if "Thank you" in resp:
        p.content(resp)
        p.ok("solved !")
    else:
        p.err("failed")

#------------------------------+
# send the data back to server |
# encoded as string            |
#------------------------------+
def net1():
    p.start("net1")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 2998))
        s.settimeout(1)
    except:
        p.err("failed to setup socket")

    data = recv(s, 4)

    if data is None:
        p.err("fail")

    num = struct.unpack("<I", data)[0]

    s.sendall(str(num))

    resp = recv(s, 32)
    s.close()

    if "correctly" in resp:
        p.content(resp)
        p.ok("solved !")
    else:
        p.err("failed")


#---------------------------------+
# add 4 numbers together and      |
# send back, numbers are LE 32bit |
#---------------------------------+
def net2():
    p.start("net2")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 2997))
        s.settimeout(1)
    except:
        p.err("failed to setup socket")

    num = 0

    for i in range(4):
        tmp = int(struct.unpack("I", recv(s, 4))[0])
        num += tmp

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        ret = struct.pack("I", num) + '\n'

    s.sendall(ret)
    resp = recv(s, 32)
    s.close()

    if "correctly" in resp:
        p.content(resp)
        p.ok("solved !")
    else:
        p.err("failed !")

#----------------------------------+
# login to the program by          |
# sending a specific byte sequence |
#----------------------------------+
def net3():
    p.start("net3")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', 2996))
        s.settimeout(1)
    except:
        p.err("failed to setup socket")

    login = '\x17'
    login += '\x05net3\x00'
    login += '\x0dawesomesauce\x00'
    login += '\x09password\x00'

    login_len = len(login)

    s.send(struct.pack('>H', login_len))
    s.send(login)

    resp = recv(s, 32).strip()
    
    if "successful" in resp:
        p.content(re.sub(r"\W", "", resp))
        p.ok("solved !")
    else: 
        p.err("failed !")

def net_solve():
    net0()
    time.sleep(1)
    net1()
    time.sleep(1)
    net2()
    time.sleep(1)
    net3()
