#!/usr/bin/env python3
##BEGIN#__________________________>#_|INFO|_#<________________________________##
##                                                           ______ _         ##
## DETAILS:                                                  | ___ (_)        ##
##- FILENAME		conf.py                                  | |_/ /___  __   ##
##- SCRIPT_ID		0x0000                                   |  __/| \ \/ /   ##
##- AUTHOR			Pixailz                                  | |   | |>  <    ##
##- CREATED			2023−06−11T22:26:16+0100                 \_|   |_/_/\_\   ##
##                                                                            ##
##END#____________________________<#_|INFO|_#>________________________________##

# main config

DEFAULT_BIN			= "./bin/ret2win"
DEFAULT_LIBC		= ""
__version__			= "0.0.0-alpha"

# cyclic length for recon
CYCLIC_LEN			= 0xff
GDB_SCRIPT			= """
b *pwnme
"""

# LOG
## padding for the level
PAD_STR				= "   "
## set loging level
### -2 disable
### -1 all
### from here N contain M < N
### 0 main title
### 1 some info
### 2 finded manifest.succ, local | remote commit id from cache
### 3 succ info
DEB_LVL				= -1
## set the column to jump with ansi code
ANSI_COL_2			= 30
SEP_COL				= "➞"

