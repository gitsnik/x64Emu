#!/usr/bin/env python

import argparse
import string
import re
import os

regs = {
	'rax': hex(0x00),
	'rbx': hex(0x00),
	'rcx': hex(0x00),
	'rdx': hex(0x00),
	'rsi': hex(0x00),
	'rdi': hex(0x00),
	'rsp': hex(0x00),
	'rbp': hex(0x00),
	'eax': hex(0x00),
	'ebx': hex(0x00),
	'ecx': hex(0x00),
	'edx': hex(0x00),
	'ax': hex(0x00),
	'bx': hex(0x00),
	'cx': hex(0x00),
	'dx': hex(0x00),
	'al': hex(0x00),
	'ah': hex(0x00),
	'bl': hex(0x00),
	'bh': hex(0x00),
	'cl': hex(0x00),
	'ch': hex(0x00),
	'dl': hex(0x00),
	'dh': hex(0x00),
}

flags = {
	'zf': hex(0x01),
}

version = 'ALPHA RELEASE v0.02'
webpage = 'http://dracyrys.com/x64Emu'

'''
	Syscalls dictionary. Pretty simple - hex code as key,
	array of two items - first is string for syscall name,
	second is "default" return value. Can be hex-as-string
	or variable name (e.g. dup2 returns what is in rsi), but
	socket() returns a sockfd, of which a single number (3)
	is enough.

	/usr/include/x86_64-linux-gnu/asm/unistd_64.h contains
	the codes in decimal, so you will need to convert to
	hex here.
'''
syscalls = {
	'0x3b': ['execve()', '0x00'],
	'0x21': ['dup2()', 'rsi'],
	'0x29': ['socket()', '0x03'],
	'0x31': ['bind()', '0x00'],
	'0x32': ['listen()', '0x00'],
	'0x2b': ['accept()', '0x04'],
	'0x0': ['read()', '0x0f'],
	'0x3c': ['exit()', 'rax'],
	'0x1': ['write()', '0x01'],
	'0x2a': ['connect()', '0x00'],
}

stack = []

'''
	Helper Function: normalise

	Clean up lines of code. Strip out comments, convert decimal to hex,
	convert everything to lower case, make sure there is proper formatting
	(e.g. spaces after commas).
'''
def normalise( line ):
	line = re.sub(r',+([^\s])', r', \1', line)
	records = line.split()

	x = 0
	retLine = ''

	while x < len(records):
		if records[x].isdigit():
			records[x] = hex( int( records[x] ) )
		retLine += ' ' + records[x]
		x += 1

	return retLine

'''
	Helper Function: is_hex

	Return true if is a 16 base integer.
'''
def is_hex( s ):
	try:
		int( s, 16 )
		return True
	except ValueError:
		return False

'''
	Helper Function: set_flag

	Exclusively for the flags registers, zf etc.
'''
def set_flag( flag, flagValue ):
	global flags

	if flag in flags:
		flags[flag] = flagValue

'''
	Helper Function: set_register

	Pass in a string of the register in lower case and the new value.
'''
def set_register( register, regValue ):
	global regs

	if regValue in regs:
		regValue = regs[regValue]

	if not is_hex( regValue ):
		regValue = hex( regValue )

	'''
		This whole thing gets tricky (mostly because I'm sure I'm doing
		it incorrectly. We take the regValue and convert it to binary,
		pad that binary out so we have the full length, then carve it
		into the respective registers (if necessary) by str(hex(binary))
		assignment.
	'''
	decimalValue = int(regValue, 16)
	binary_value = bin(decimalValue)[2:].zfill(64)

	reg64bit = False
	reg64bitValue = False

	'''
		When working on the smaller registers, we always want to use the
		last n bytes of binary_value. This makes less sense when working
		with h style registers - we want the last 8 bytes because we only
		pass in 8 bytes (so the binary_value pads to be 56 zeroes before
		the bytes we need).
	'''
	if register[-1:] == 'l':
		full_register = "r%sx" % register[:1]

		curr_value = bin(int(regs[full_register], 16))[2:].zfill(64)
		new_value = (str(curr_value[:-8]) + str(binary_value[-8:]))

		reg64bit = full_register
		reg64bitValue = new_value

		regs[full_register] = new_value

	elif register[-1:] == 'h':
		full_register = "r%sx" % register[:1]

		curr_value = bin(int(regs[full_register], 16))[2:].zfill(64)
		new_value = (str(curr_value[:-16]) + str(binary_value[-8:]) + str(curr_value[-8:]))

		reg64bit = full_register
		reg64bitValue = new_value

		regs[full_register] = new_value

	elif register[:1] == 'e':
		full_register = "r%sx" % register[1:2]

		curr_value = bin(int(regs[full_register], 16))[2:].zfill(64)
		new_value = (str(curr_value[:-32]) + str(binary_value[-32:]))

		reg64bit = full_register
		reg64bitValue = new_value

		regs[full_register] = new_value

	elif register[:1] == 'r' and register[-1:] == 'x':
		full_register = register

		new_value = str(binary_value)

		reg64bit = full_register
		reg64bitValue = new_value

		regs[full_register] = new_value

	elif register[-1:] == 'x':
		full_register = "r%sx" % register[:1]

		curr_value = bin(int(regs[full_register], 16))[2:].zfill(64)
		new_value = (str(curr_value[:-16]) + str(binary_value[-16:]))

		reg64bit = full_register
		reg64bitValue = new_value

		regs[full_register] = new_value

	else:
		regs[register] = regValue

	'''
		We have now generated "new" 64 bit values for the r*x register, we need to
		update those appropriately for e*x, *x, *h, and *l.
	'''
	if reg64bit:
		reg32bit = "e%sx" % reg64bit[1:2]
		reg16bit = "%sx" % reg64bit[1:2]
		regHigh = "%sh" % reg64bit[1:2]
		regLow = "%sl" % reg64bit[1:2]
		regs[reg64bit] = hex(int(str(reg64bitValue), 2))
		regs[reg32bit] = hex(int(str(reg64bitValue[32:]), 2))
		regs[reg16bit] = hex(int(str(reg64bitValue[-16:]), 2))
		regs[regHigh] = hex(int(str(reg64bitValue[-16:-8]), 2))
		regs[regLow] = hex(int(str(reg64bitValue[-8:]), 2))


def push_stack( stackValue ):
	global stack
	stack.append( stackValue )

def pop_stack():
	global stack
	return stack.pop()

'''
	Main command processing area.

	Effectively one big if/elif/else loop. Pretty simple to
	implement a new command. Put in an elif commands[0] == 'mov':
	and use set_register( 'rax', "12" ) when you have finished
	your processing.

	Stack not yet implemented.
'''
def command( line ):
	if line[-1:] == ":":
		return False

	line = normalise( line )

	commands = line.split()

	if len(commands) > 1:
		register = commands[1].replace(',', '')

	if commands[0] == 'mov':
		if is_hex( commands[2] ):
			set_register( register, commands[2] )
		else:
			movVal = regs[commands[2]]
			set_register( register, movVal )
	elif commands[0] == 'scasq':
		# Assume the string scanned correctly.
		set_flag( 'zf', 1 )
	elif commands[0] == 'xor':
		newValue = commands[2]

		if newValue in regs:
			newValue = regs[newValue]

		curValue = int(regs[register], 16)
		newValue = int(newValue, 16)

		xorValue = str(curValue ^ newValue)

		set_register( register, xorValue )
	elif commands[0] == 'sub':
		newValue = hex( int(regs[register], 16) - int(commands[2], 16))
		set_register( register, newValue )
	elif commands[0] == 'add':
		newValue = hex(int(regs[register], 16) + int(commands[2], 16))
		set_register( register, newValue )
	elif commands[0] == 'dec':
		newValue = hex(int(regs[register], 16) - 1)
		set_register( register, newValue )
	elif commands[0] == 'inc':
		newValue = hex(int(regs[register], 16) + 1)
		set_register( register, newValue )
	elif commands[0] == 'push':
		if register == 'byte':
			push_stack( commands[2] )
		elif is_hex( register ):
			push_stack( commands[1] )
		else:
			pushValue = regs[register]
			push_stack( pushValue )
	elif commands[0] == 'pop':
		stackVal = pop_stack()
		set_register( register, stackVal )
	elif commands[0] == 'mul':
		# mul rax by register, return result into rax
		curValue = int(regs['rax'], 16)
		newValue = int(regs[register], 16)
		mulValue = str(curValue * newValue)

		set_register( 'rax', mulValue )

		if int(regs['rax'], 16) == hex(0x00):
			set_flag( 'zf', 1 )
		else:
			set_flag( 'zf', 0 )
	elif commands[0] == 'xchg':
		oneVal = regs[register]
		set_register( register, regs[commands[2]] )
		set_register( commands[2], oneVal )
	elif commands[0] == 'syscall':
		if str(regs['rax']) in syscalls:
			print("[+] %s : success rax = %s" % (syscalls[str(regs['rax'])][0], str(syscalls[regs['rax']][1])))
			set_register( "rax", syscalls[regs['rax']][1] )
			if regs['rax'] == '0x0':
				set_flag( 'zf', 1 )
			else:
				set_flag( 'zf', 0 )
		else:
			print("[-] unknown (%s) : default rax = 0" % str(regs['rax']))
			set_register( "rax", "0" )
	elif commands[0] == 'cdq':
		# Technically this is supposed to extend the sign of EAX into a quad word for EAX and EDX
		# Basically we're going to "trust" that it is used properly in shellcode, so we just use it
		# as a null instruction for RDX.
		set_register( "rdx", "0" )
	elif commands[0] == 'bits' or commands[0] == 'global' or commands[0] == 'section':
		return 0
	elif commands[0] == 'jz' or commands[0] == 'je':
		if flags['zf'] == 1:
			set_flag( 'zf', 0 )
			return register
	elif commands[0] == 'jnz' or commands[0] == 'jne':
		if flags['zf'] == 0:
			return register
	else:
		print("Unknown commands %s" % commands[0])

	return 0

'''
	Helper Function: print_regs

	Print the registers out. Will later print stack as well.
'''
def print_regs(verbosity = 0):
	print("RAX: %-18s RBX: %-18s RCX: %-18s RDX: %-18s RSI: %-18s RDI: %-18s RSP: %-18s" % (regs['rax'], regs['rbx'], regs['rcx'], regs['rdx'], regs['rsi'], regs['rdi'], regs['rsp']) )
	if verbosity > 2:
		print("EAX: %-18s  AX: %-18s  AH: %-18s  AL: %-18s  ZF: %-18s" % (regs['eax'], regs['ax'], regs['ah'], regs['al'], flags['zf']))

'''
	Main Processing Loop. Pretty much an open file, parse, and move on loop at this stage.
'''
def main():
	desc = "x86_64 Simple Shellcode Analysis Program [%s]%s%s" % (version, os.linesep, webpage)
	parser = argparse.ArgumentParser(description=desc)
	parser.add_argument("filename")
	parser.add_argument("-v", "--verbose", help="Increase Output Verbosity (Practical Maximum 3 times)", action="count")
	args = parser.parse_args()

	labelName = ""
	with open( args.filename ) as f:
		for line in f:
			line = line.split(";", 1)[0]
			line = line.rstrip()
			line = line.lstrip()
			if labelName == "":
				if line:
					ret = command( line )
					if isinstance( ret, str ):
						labelName = ("%s:" % ret)
						f.seek(0)
						if args.verbose >= 1:
							print( "Seeking to Label [%s]" % labelName )
					if args.verbose >= 1:
						print( line )
						if args.verbose >= 2:
							print_regs(args.verbose)
			else:
				if line == labelName:
					labelName = ""

if __name__ == "__main__":
	main()
