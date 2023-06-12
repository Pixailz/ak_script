#!/usr/bin/env python3
##BEGIN#__________________________>#_|INFO|_#<________________________________##
##                                                           ______ _         ##
## DETAILS:                                                  | ___ (_)        ##
##- FILENAME		pars.py                                  | |_/ /___  __   ##
##- SCRIPT_ID		0x0000                                   |  __/| \ \/ /   ##
##- AUTHOR			Pixailz                                  | |   | |>  <    ##
##- CREATED			2023−06−11T22:26:16+0100                 \_|   |_/_/\_\   ##
##                                                                            ##
##END#____________________________<#_|INFO|_#>________________________________##

import argparse
from sys			import argv

from utils.conf		import DEFAULT_BIN
from utils.conf		import DEFAULT_LIBC
from utils.conf		import __version__

parsing = argparse.ArgumentParser(
	description="Auto ak some binary"
)

parsing.add_argument(
	"-t", "--target",
	help="choose the binary to target",
	default=DEFAULT_BIN,
	type=str,
	required=False
)

parsing.add_argument(
	"--libc",
	help="specify a libc binary",
	default=DEFAULT_LIBC,
	type=str,
	required=False
)

parsing.add_argument(
	"-r", "--remote",
	help="run remotly",
	default=False,
	action="store_true"
)

parsing.add_argument(
	"-v", "--version",
	action="version",
	version=f"%(prog)s {__version__}"
)

parsing.add_argument(
	"-g", "--gdb",
	help="should attach gdb with pwn tool",
	action="store_true",
	required=False
)

if "-r" in argv or "--remote" in argv:
	h_and_p_required=True
else:
	h_and_p_required=False

parsing.add_argument(
	"-H", "--host",
	help="host for the remote connection",
	required=h_and_p_required,
	type=str,
)

parsing.add_argument(
	"-p", "--port",
	help="port for the remote connection",
	required=h_and_p_required,
	type=int,
)

parsed = parsing.parse_args()
