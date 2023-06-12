#!/usr/bin/env python3
##BEGIN#__________________________>#_|INFO|_#<________________________________##
##                                                           ______ _         ##
## DETAILS:                                                  | ___ (_)        ##
##- FILENAME		bin.py                                   | |_/ /___  __   ##
##- SCRIPT_ID		0x0000                                   |  __/| \ \/ /   ##
##- AUTHOR			Pixailz                                  | |   | |>  <    ##
##- CREATED			2023−06−11T22:26:16+0100                 \_|   |_/_/\_\   ##
##                                                                            ##
##END#____________________________<#_|INFO|_#>________________________________##

from pwn			import ELF, ROP, p64, p32, gdb

from os.path		import isfile

from utils.parse	import parsed
from utils.log		import log, LM
from utils.conf		import GDB_SCRIPT

class Bin():
	#?> INIT
	def	__init__(self, path, libc):
		self.path_bin = path
		self.path_lib = libc
		self.lod = None
		self.rop = None
		self.pro = None
		self.core_dp = None
		self.arch = None
		self.f_p = None
		self.bp = None
		self.ip = None
		self.dr = None
		self.sym = dict()
		self.pwn_load()

	def	pwn_load(self):
		if self.path_bin != None:
			if isfile(self.path_bin):
				log.format(f"{self.path_bin} found loading it", LM.SUCCESS, 0)
				self.pwn_load_bin()
			else:
				log.format(f"{self.path_bin} not found. exiting", LM.FAILURE, 0)
				exit(1)
		if self.path_lib != None and isfile(self.path_lib):
			log.format(f"{self.path_lib} found loading it", LM.SUCCESS, 0)
			self.pwn_load_lib()

	def	pwn_load_bin(self):
		self.lod = ELF(self.path_bin)
		self.rop = ROP(self.lod)
		self.arch = self.lod.arch
		# Some thing may change between amd64 and i386
		if self.arch == "amd64":
			self.f_p = p64
			self.bp = "rbp"
			self.ip = "rip"
			self.dr = "rdi"
		elif self.arch == "i386":
			self.f_p = p32
			self.bp = "ebp"
			self.ip = "eip"
			self.dr = "edi"

	def	pwn_load_lib(self):
		self.lib_lod = ELF(self.path_lib)
		self.lib_rop = ROP(self.lib_lod)

	def	pwn_load_remote(self):
		self.pro = remote(parsed.host, parsed.port)

	def	pwn_load_local(self):
		if self.lod != None:
			self.pro = self.lod.process()

	def	pwn_load_local_gdb(self):
		if self.lod != None and parsed.gdb:
			gdb.attach(self.pro.pid, GDB_SCRIPT, api=True)
	#?< INIT
	#?> UTIL
	def	pwn_sym_get(self, name, value):
		try:
			tmp_sym = self.lod.symbols[value]
		except KeyError:
			try:
				tmp_sym = self.lod.got[value]
			except KeyError:
				tmp_sym = None
		if tmp_sym != None:
			log.col_2(f"{value} addr found at ", hex(tmp_sym), LM.SUCCESS)
		else:
			log.format(f"{value} addr not found", LM.FAILURE)
		self.sym[name] = tmp_sym
	#?< UTIL

