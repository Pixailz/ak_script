#!/bin/env python3

import argparse
import os
from sys import argv as _ARGV
from pwn import *

_DEFAULT_BIN = ""
__version__ = "0.0.0-alpha"

class AkAuto():

	@staticmethod
	def parse_args():
		parser = argparse.ArgumentParser(
			description="Auto ak some binary"
		)
		group = parser.add_mutually_exclusive_group(required=False)
		group.add_argument(
			"-t", "--target",
			help="choose the binary to target",
			default=_DEFAULT_BIN,
			type=str,
			required=False
		)
		group.add_argument(
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

	def load_binary(self):
		context.binary = self._elf_loaded = ELF(self.args.target)
		self._rop_loaded = ROP(self._elf_loaded)

	def __init__(self):
		self.args = self.parse_args()
		self.load_binary()


if __name__ == "__main__":
	ak = AkAuto()
