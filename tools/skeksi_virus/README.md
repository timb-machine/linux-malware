# skeksi_virus

Linux X86_64 ELF Virus that just might ruin someones day in the wrong hands

## General about

This Virus is humurous, but it is also nasty and should not be executed on any system unless
it is a controlled environmnent, or an expendable Virtual machine setup specifically to host
malware. The Skeksi Virus was written merely for the sake of inventiveness, and to demonstrate
how to write a quality Virus for Linux, mostly in C. It is a work in progress and is not yet
complete. 

## Virus specifications

### Infection techniques

* Extends text segment in reverse to make room for parasite

This technique is nice, because it is less suspicious. The entry point still points into the
.text section of the executable, and there is no modifications to the segment permissions or
segment type (such as converting a PT_NOTE to PT_LOAD).

* Infects the PLT/GOT

Currently the Virus only looks for the puts() function which is used to print strings and is
often linked into an executable instead of printf(). The result is that an infected binary will
print everything to stdout in l33t sp34k, randomly with a probability of 1 in 5.

## Infection behaviour 

The virus will infect only x86_64 ELF ET_EXEC binaries that are dynamically linked. The virus
will soon also be able to infect shared libaries, but some adjustments must be made to take
into account the position independent type executables. The virus will mark an infected file's
EI_PAD area (9 bytes into the ELF file header) with a magic number 0x15D25. This prevents it
from re-infecting a given file.

If the Virus is launched as a non-root user, it will only infect binaries in the CWD. If the
virus is launched with root privileges it will randomly select one of four directories: 
/bin, /usr/bin, /sbin, /usr/sbin. After it picks a target directory it will have a 1 in 10
chance of infecting each file as it iterates through all of them.

## Nuances and notes

Notice we do store string literals, not just on the stack. This is because the text and data
segment are merged into a single segment and each time the virus copies itself, it copies
all of the string data as well.
