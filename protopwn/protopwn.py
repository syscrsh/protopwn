from stacksolver import *
from netsolver import *
from formatsolver import *
from heapsolver import *
from finalsolver import *

PATH="/opt/protostar/bin/"

def banner():
    line = str()
    line += "\n+-------------------------------+\n"
    line += "| Protostar Exploit v1.0        |\n"
    line += "+-------------------------------+\n"
    line += "| written with <3 and coffee by |\n"
    line += "| Twitter - @systemcra_sh       |\n"
    line += "| https://blog.systemcra.sh     |\n"
    line += "| October 2021                  |\n"
    line += "+-------------------------------+\n"
    print(line)

def start(levelname):
    print("[ * ] --------- [ " + levelname + " ] -------")

def ok(msg):
    print("[ + ] " + msg)

def dump(payload):
    print("[ ! ] dumping payload to disk ...")
    f = open("/tmp/payload_dump", "w")
    f.writelines(payload)
    f.close()
    exit

def warn(msg):
    print("[ ! ] " + msg)

def dbg(msg):
    print("[ ! ] " + msg)
    exit()

def info(msg):
    print("[ * ] " + msg)

def content(msg):
    print("[ * ] output -> { " + msg.strip() + " }")

def err(msg):
    print("[ x ] " + msg)
    exit()

if __name__ == "__main__":
    os.chdir(PATH)
    banner()
    format_solve()
    stack_solve()
    net_solve()
    heap_solve()
    final_solve()
