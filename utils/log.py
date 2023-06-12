#!/usr/bin/env python3
##BEGIN#__________________________>#_|INFO|_#<________________________________##
##                                                           ______ _         ##
## DETAILS:                                                  | ___ (_)        ##
##- FILENAME		log.py                                   | |_/ /___  __   ##
##- SCRIPT_ID		0x0000                                   |  __/| \ \/ /   ##
##- AUTHOR			Pixailz                                  | |   | |>  <    ##
##- CREATED			2023−06−11T22:26:16+0100                 \_|   |_/_/\_\   ##
##                                                                            ##
##END#____________________________<#_|INFO|_#>________________________________##

from utils.conf	import DEB_LVL, PAD_STR, ANSI_COL_2, SEP_COL

from enum		import Enum, auto

class LM(Enum):
	SUCCESS	= auto()
	FAILURE	= auto()
	INFO		= auto()
	WARN		= auto()
	VOID		= auto()

# 	def	log_payload(self, title, payload):
# 		payload_decoded = ''.join(
# 			[ "\\x" + f"{b:X}".rjust(2, '0') for b in payload ]
# 		)
# 		self.log_padded(title, payload_decoded, 1)


class Log():
	def	__init__(self, debug_level=DEB_LVL):
		self.ESC = "\x1b"
		self.R = f"{self.ESC}[31m"
		self.G = f"{self.ESC}[32m"
		self.Y = f"{self.ESC}[33m"
		self.B = f"{self.ESC}[34m"

		self.BLD = f"{self.ESC}[1m"
		self.RST = f"{self.ESC}[00m"

		self.S_head = f"[{self.BLD}{self.G}+{self.RST}]"
		self.I_head = f"[{self.BLD}{self.B}*{self.RST}]"
		self.W_head = f"[{self.BLD}{self.Y}!{self.RST}]"
		self.E_head = f"[{self.BLD}{self.R}-{self.RST}]"

	def	format(self, string, mode=LM.INFO, level=0):
		head = self.get_head(mode)
		if DEB_LVL == -1 or level <= DEB_LVL:
			tmp_padding = PAD_STR * level
			print(f"{tmp_padding}{head}{string}")

	def	get_head(self, mode):
		if mode == LM.SUCCESS:
			return (self.S_head + ' ')
		if mode == LM.FAILURE:
			return(self.E_head + ' ')
		if mode == LM.INFO:
			return(self.I_head + ' ')
		if mode == LM.WARN:
			return(self.W_head + ' ')
		if mode == LM.VOID:
			return("")

	def	col_2(self, col1, col2, mode=LM.INFO, level=0):
		col_pos = ANSI_COL_2 + (level * len(PAD_STR))
		self.format(f"{col1}{self.ESC}[{col_pos}G{SEP_COL} {col2}", mode, level)

	def	p_list(self, mode=LM.INFO, level=0, *items):
		for item in items:
			self.format(f"{item}", 4, level)

	def	stdout(self, level, *items):
		self.format('stdout', LM.SUCCESS, level)
		for item in items:
			to_print = f"[{item}]" if len(item) else ""
			self.format(to_print, LM.VOID, level)
log = Log()
