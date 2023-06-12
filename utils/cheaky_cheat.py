#!/usr/bin/env python3
##BEGIN#__________________________>#_|INFO|_#<________________________________##
##                                                           ______ _         ##
## DETAILS:                                                  | ___ (_)        ##
##- FILENAME		cheaky.py                                | |_/ /___  __   ##
##- SCRIPT_ID		0x0000                                   |  __/| \ \/ /   ##
##- AUTHOR			Pixailz                                  | |   | |>  <    ##
##- CREATED			2023−06−12T01:32:40+0100                 \_|   |_/_/\_\   ##
##                                                                            ##
##END#____________________________<#_|INFO|_#>________________________________##

from utils.log		import log, LM

SENDLINEAFTER		= 0
SENDLINE			= 1
RECVUNTIL			= 2

class	CheakyCheat():
	def	__init__(self):
		self.clear_step_list()

	def	clear_step_list(self):
		self.step_list = list()

	def set_process(self, process):
		self.process = process

	def	exec_cheat(self, print_out=True):
		stdout = ""
		for step in self.step_list:
			if step[0] == SENDLINEAFTER:
				log.format(f"exec sendlineafter(\"{step[1]}\",\"{step[2]}\")", LM.INFO, 1)
				stdout = self.process.sendlineafter(step[1], step[2])
				stdout = stdout.decode("utf-8").split('\n')
			elif step[0] == SENDLINE:
				log.format(f"exec sendline(\"{step[1]}\")", LM.INFO, 1)
				stdout = self.process.sendline(step[1])
				stdout = self.process.clean().decode("utf-8").split('\n')
			elif step[0] == RECVUNTIL:
				log.format(f"exec revuntil(\"{step[1]}\")", LM.INFO, 1)
				stdout = self.process.recvuntil(step[1])
			if print_out:
				log.stdout(2, *stdout)

	def	add_sendafterline(self, delim, value):
		if type(delim) == str:
			delim = delim.encode()
		if type(value) == str:
			value = value.encode()
		self.step_list.append([ SENDLINEAFTER, delim, value ])

	def	add_sendline(self, value):
		if type(value) == str:
			value = value.encode()
		self.step_list.append([ SENDLINE, value])

	def	add_recvuntil(self, value):
		if type(value) == str:
			value = value.encode()
		self.step_list.append([ RECVUNTIL, value])
