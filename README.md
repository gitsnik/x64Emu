x64Emu
======

x64 Intel Nasm Syntax Emulator

-- With a significant nod to the LibEMU project and the fantastic work they have done.

The x64-emu.py script is a simple python script to emulate a 64bit register. It has been
designed for use primarily because scanning through 64 bit shellcode with GDB is a time
consuming process and one is constantly looking up syscall numbers.

The premise is simple - each syscall has a "default" return value, socket() returns a
socket (an integer greater than 2) so we can guess a little and give it a value. Examination
of the syscall dictionary will show some examples (pay specific attention to dup2, which
will return the value in rsi as an example).

Usage
=====

usage: analysis.py [-h] [-v] filename

x86_64 Simple Shellcode Analysis Program [ALPHA RELEASE v0.01]

positional arguments:

  filename

optional arguments:

  -h, --help     show this help message and exit

  -v, --verbose  Increase Output Verbosity (once for printing lines as they
                 are read, twice for registers as well)

This works with Intel Nasm syntax, and it sort of relies on having the original
source code. You can do the following to make a mostly readable, mostly automatic
dump of any shellcode you encounter.

objdump -M intel -D shellcode | \

tr '\t' ' ' | \

perl -pe 's/.[^:]*:( [a-f0-9]{2})+//g; s/(^ +|>)//g; s/ +/ /g; s/^[0-9a-f]+ <//g; s/(j?e) [0-9a-f]+ </$1 /g'

Notice that is one big processing line. The only other thing you will need to do
is, probably manually, clean up any scas lines as the syscall "interpreter" doesn't really understand
multi argument calls.

Piping your output through this seems to work.

perl -pe 's/scas rax.(.).*/scas$1/g;' | tr '[:upper:]' '[:lower:]'
