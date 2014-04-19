x64Emu
======

x64 Intel Nasm Syntax Emulator ( http://dracyrys.com/x64Emu )

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

```
usage: x64-emu.py [-h] [-v] [-o] filename

x86_64 Simple Shellcode Analysis Program [ALPHA RELEASE v0.02]
http://dracyrys.com/x64Emu

positional arguments:

  filename

optional arguments:
  -h, --help      show this help message and exit
  -v, --verbose   Increase Output Verbosity (Practical Maximum 3 times)
  -o, --optimize  Display simple optimization tips. Not perfect, still helpful
```

This works with Intel Nasm syntax, and it sort of relies on having the original
source code. You can do the following to make a mostly readable, mostly automatic
dump of any shellcode you encounter.

```
objdump -M intel -D shellcode | \
tr '\t' ' ' | \
perl -pe 's/.[^:]*:( [a-f0-9]{2})+//g; s/(^ +|>)//g; s/ +/ /g; s/^[0-9a-f]+ <//g; s/(j?e) [0-9a-f]+ </$1 /g'
```

Notice that is one big processing line. The only other thing you will need to do
is, probably manually, clean up any scas lines as the syscall "interpreter" doesn't really understand
multi argument calls.

Piping your output through this seems to work.

```perl
perl -pe 's/scas rax.(.).*/scas$1/g;' | tr '[:upper:]' '[:lower:]'
```

Optimisation
============

The optimisation routine works for simple checks. If a register is already null, making it null again is
generally a useless gesture. There are some commands that will not trigger the optimisation routine (xor
for example) because the majority of the time this is not a mistaken command to create nulls with.

Optimisation will also check for null statement commands - mov rax, 0x59 for example will generate a full
64bit pad of nulls before 59 so the system reports this to you. Future releases may even process a suggested
code exchange for you.

Known Bugs
==========

Moving large numbers directly into 64bit registers (that is, anything larger than  0x7fffffffffffffff) will cause python to complain of a value error:

ValueError: invalid literal for int() with base 16: '0x950b11acaaaaff02L'

