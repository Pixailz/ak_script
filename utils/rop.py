#!/usr/bin/env python3
##BEGIN#__________________________>#_|INFO|_#<________________________________##
##                                                           ______ _         ##
## DETAILS:                                                  | ___ (_)        ##
##- FILENAME		rop.py                                   | |_/ /___  __   ##
##- SCRIPT_ID		0x0000                                   |  __/| \ \/ /   ##
##- AUTHOR			Pixailz                                  | |   | |>  <    ##
##- CREATED			2023−06−11T23:23:24+0100                 \_|   |_/_/\_\   ##
##                                                                            ##
##END#____________________________<#_|INFO|_#>________________________________##

from utils.bin import Bin
from utils.log import log, LM

class Rop():
	def	__init__(self, bin):
		"""
			pack items with pack_func, and join as byte
			pack_func could be either p64 or p32, depending on Bin.f_p
		"""
		self.bin = bin
		self.rop_items = dict()
		# default usefull rop
		self.load_rop("ret", "ret")
		self.load_rop("pop_rdi", "pop rdi", "ret")

	def	dbg_print_rop_items(self):
		for key, value in self.rop_items.items:
			print(f"{key} \x1b[15G{value}")

	def	load_rop(self, name, *inst):
		if self.bin.rop != None:
			try:
				self.rop_items[name] = self.bin.rop.find_gadget(inst)[0]
			except TypeError:
				log.format(f"rop {name} not found.", LM.FAILURE)
			else:
				log.col_2(f"rop found {{{hex(self.rop_items[name])}}}", name, LM.SUCCESS)
