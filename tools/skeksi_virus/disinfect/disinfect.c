/*
 * Skeksi Virus disinfector, by ElfMaster. January 2016
 *
 * -= About:
 * This disinfector is the first prototype, it is written for those who may have been so unfortunate
 * as to infect their own system. The disinfector will work any infected ET_EXEC file, provided that
 * it has section headers. This is somewhat of a weakness considering the Virus itself works on executables
 * that have no section headers. If you need to change this, its pretty easy, just parse the program
 * headers and get PT_DYNAMIC, and then use the D_TAG's to find the PLT/GOT, Relocation, and dynamic
 * symbol table. 
 *
 * -= Usage:
 * gcc -O2 skeksi_disinfect.c -o disinfect
 * ./disinfect <executable>

 * elfmaster [4t] zoho.com
 */

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <errno.h>

typedef struct elfdesc {
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	Elf64_Addr textVaddr;
	Elf64_Addr dataVaddr;
	Elf64_Addr dataOff;
	size_t textSize;
	size_t dataSize;
	uint8_t *mem;
	struct stat st;
	char *path;
} elfdesc_t;

#define TMP ".disinfect_file.xyz"

/*
 * If we find push/ret, and the address
 * being pushed is within the text segment
 * of the regular x86_64 text range per the
 * default linker script, then we are probably
 * in good shape. 
 * note: 0x400000 is the default text base
 */
uint32_t locate_orig_entry(elfdesc_t *elf)
{
	uint32_t i, entry;
        uint8_t *mem = elf->mem;
        for (i = 0; i < elf->st.st_size; i++) {
                if (mem[0] == 0x68 && mem[5] == 0xc3) {
			entry = *(uint32_t *)&mem[1];
			if (entry >= 0x400000 && entry < 0x4fffff) 
				return entry;
		}
	}
	return 0; // couldn't find it, uh oh!
}	

uint32_t locate_glibc_init_offset(elfdesc_t *elf)
{
	uint32_t i;
	uint8_t *mem = elf->mem;
	
	for (i = 0; i < elf->st.st_size; i++) {
		if (
		mem[i + 0] == 0x31 && mem[i + 1] == 0xed &&
		mem[i + 2] == 0x49 && mem[i + 3] == 0x89 &&
		mem[i + 4] == 0xd1 && mem[i + 5] == 0x5e &&
		mem[i + 6] == 0x48 && mem[i + 7] == 0x89 && mem[i + 8] == 0xe2)
			return i;
	}

	return 0;
}
	
int disinfect_pltgot(elfdesc_t *elf)
{
	Elf64_Ehdr *ehdr = elf->ehdr;
	Elf64_Phdr *phdr = elf->phdr;
	Elf64_Shdr *shdr = elf->shdr;
	uint8_t *mem = elf->mem;
	Elf64_Sym *symtab = NULL;
	Elf64_Rela *rela = NULL;
	Elf64_Addr addr = 0, plt_addr = 0;
	Elf64_Off plt_off = 0, gotoff = 0;
	size_t plt_size = 0, symtab_size = 0, rela_size = 0;
  	char *shstrtab = (char *)&mem[shdr[elf->ehdr->e_shstrndx].sh_offset];
	char *strtab = NULL;
	uint8_t *gotptr, *plt;
	int i, j, symindex = 0, c = 0;

	for (i = 0; i < ehdr->e_shnum; i++) {
		switch(shdr[i].sh_type) {
			case SHT_DYNSYM:
				symtab = (Elf64_Sym *)&mem[shdr[i].sh_offset];
				symtab_size = shdr[i].sh_size;
				strtab = (char *)&mem[shdr[shdr[i].sh_link].sh_offset];
				break;
			case SHT_RELA:
				if (!strcmp(&shstrtab[shdr[i].sh_name], ".rela.plt")) {
					rela = (Elf64_Rela *)&mem[shdr[i].sh_offset];
					rela_size = shdr[i].sh_size;
				}
				break;	
			case SHT_PROGBITS:
				if (!strcmp(&shstrtab[shdr[i].sh_name], ".plt")) {
					plt_off = shdr[i].sh_offset;
					plt_addr = shdr[i].sh_addr;
					plt_size = shdr[i].sh_size;
				}
				break;
		}
	}
	if (plt_off == 0 || symtab == NULL || rela == NULL) {
		printf("Unable to find relocation/symbol/plt info\n");
		return -1;
	}
	
	plt = &mem[plt_off]; // point at PLT, right past PLT-0
	for (i = 0; i < rela_size/sizeof(Elf64_Rela); i++) {
		
		symindex = ELF64_R_SYM(rela->r_info);
		if (!strcmp(&strtab[symtab[ELF64_R_SYM(rela->r_info)].st_name], "puts")) {
			printf("Attempting to disinfect PLT/GOT\n");
			gotoff = elf->dataOff + (rela->r_offset - elf->dataVaddr);
			gotptr = &mem[gotoff];
			addr = gotptr[0] + (gotptr[1] << 8) + (gotptr[2] << 16) + (gotptr[3] << 24);
			if (!(addr >= plt_addr && addr < plt_addr + plt_size)) {
				for (c = 0, j = 0; j < plt_size; j += 16, c++) {
					if (c == symindex) {
						printf("Successfully disinfected PLT/GOT table\n");
						*(uint32_t *)gotptr = plt_addr + j + 6;
						return 0;
					}	
				}	

			}
			printf("Failed to disinfect PLT/GOT table\n");
			return -1;
		}
	}
	
	return 0;
}

/*
 * Expected x86_64 base is 0x400000 in Linux. We rely on that
 * here, which may end up being a bit wobbly.
 */
int disinfect(elfdesc_t *elf)
{
	size_t paddingSize;
	Elf64_Phdr *phdr = elf->phdr;
	Elf64_Shdr *shdr = elf->shdr;
	uint32_t text_offset = 0;
	char *strtab = NULL;
	uint8_t *mem = elf->mem;
	int i, textfound, fd;
	ssize_t c, last_chunk;
	if (elf->textVaddr >= 0x400000) {
		printf("unexpected text segment address, this file may not actually be infected\n");
		return -1;
	}

	paddingSize = 0x400000 - elf->textVaddr;
	
	/*
	 * Remove PLT/GOT hooks if present
	 */
	int ret = disinfect_pltgot(elf);
	
	/*
	 * Remove infection magic
	 */
	*(uint32_t *)&elf->ehdr->e_ident[EI_PAD] = 0x00000000;

	/*
	 * PT_PHDR, PT_INTERP were pushed forward in the file
	 */
	phdr[0].p_offset -= paddingSize;
	phdr[1].p_offset -= paddingSize;
	
	/*
	 * Set phdr's back to normal
	 */
	for (textfound = 0, i = 0; i < elf->ehdr->e_phnum; i++) {
		if (textfound) {
			phdr[i].p_offset -= paddingSize;
			continue;
		}
		if (phdr[i].p_type == PT_LOAD && phdr[i].p_offset == 0 && phdr[i].p_flags & PF_X) {
			if (phdr[i].p_paddr == phdr[i].p_vaddr) {
				phdr[i].p_vaddr += paddingSize;
				phdr[i].p_paddr += paddingSize;
			} else
				phdr[i].p_vaddr += paddingSize;
			/*
			 * reset segment size for text
			 */
			phdr[i].p_filesz -= paddingSize;
			phdr[i].p_memsz -= paddingSize;
			phdr[i].p_align = 0x200000;
			phdr[i + 1].p_align = 0x200000;
			textfound = 1;
		}
	}
	
	text_offset = locate_glibc_init_offset(elf);

	/*
	 * Straighten out section headers
	 */
	strtab = (char *)&mem[shdr[elf->ehdr->e_shstrndx].sh_offset];
	for (i = 0; i < elf->ehdr->e_shnum; i++) {
		/*
	 	 * We treat .text section special because it is modified to 
		 * encase the entire parasite code. Lets change it back to 
		 * only encasing the regular .text stuff.
		 */
		if (!strcmp(&strtab[shdr[i].sh_name], ".text")) {
			if (text_offset == 0) // leave unchanged :(
				continue;
			shdr[i].sh_offset = text_offset - paddingSize;
			shdr[i].sh_addr = (text_offset - paddingSize) + 0x400000;
			continue;
		}
		shdr[i].sh_offset -= paddingSize;
	}
	
	/*
	 * Set phdr and shdr table back
	 */
	elf->ehdr->e_shoff -= paddingSize;
	elf->ehdr->e_phoff -= paddingSize;
           
	/*
	 * Set original entry point
	 */
	elf->ehdr->e_entry = 0x400000 + text_offset;
      	elf->ehdr->e_entry -= paddingSize;

	if ((fd = open(TMP, O_CREAT | O_TRUNC | O_WRONLY, elf->st.st_mode)) < 0) 
		return -1;

	if ((c = write(fd, mem, sizeof(Elf64_Ehdr))) != sizeof(Elf64_Ehdr)) 
		return -1;

	mem += paddingSize + sizeof(Elf64_Ehdr);
	last_chunk = elf->st.st_size - (paddingSize + sizeof(Elf64_Ehdr));
	
	if ((c = write(fd, mem, last_chunk)) != last_chunk) 
		return -1;

	if (fchown(fd, elf->st.st_uid, elf->st.st_gid) < 0)
		return -1;

	rename(TMP, elf->path);
	
	return 0;
}

int load_executable(const char *path, elfdesc_t *elf)
{
	uint8_t *mem;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	int fd;
	struct stat st;
	int i;

	if ((fd = open(path, O_RDONLY)) < 0) {
		perror("open");
		return -1;
	}
	fstat(fd, &st);
	
	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	
	ehdr = (Elf64_Ehdr *)mem;
	phdr = (Elf64_Phdr *)&mem[ehdr->e_phoff];
	shdr = (Elf64_Shdr *)&mem[ehdr->e_shoff];
	
	elf->st = st;
	
	for (i = 0; i < ehdr->e_phnum; i++) {
		switch(!!phdr[i].p_offset) {
			case 0:
				elf->textVaddr = phdr[i].p_vaddr;
				elf->textSize = phdr[i].p_filesz;
				break;
			case 1:
				elf->dataOff = phdr[i].p_offset;
				elf->dataVaddr = phdr[i].p_vaddr;
				elf->dataSize = phdr[i].p_filesz;
				break;
		}
	}
	elf->mem = mem;
	elf->ehdr = ehdr;
	elf->phdr = phdr;
	elf->shdr = shdr;
	elf->path = (char *)path;
	return 0;
	
}
	
int test_for_skeksi(elfdesc_t *elf)
{
	uint32_t magic = *(uint32_t *)&elf->ehdr->e_ident[EI_PAD];
	return (magic == 0x15D25); 
}

int main(int argc, char **argv)
{
	elfdesc_t elf;

	if (argc < 2) {
		printf("Usage: %s <executable>\n", argv[0]);
		exit(0);
	}
	
	if (load_executable(argv[1], &elf) < 0) {
		printf("Failed to load executable: %s\n", argv[1]);
		exit(-1);
	}
	
	if (test_for_skeksi(&elf) == 0) {
		printf("File: %s, is not infected with the Skeksi virus\n", argv[1]);
		exit(-1);
	}
	printf("File: %s, is infected with the skeksi virus! Attempting to disinfect\n", argv[1]);

	if (disinfect(&elf) < 0) {
		printf("Failed to disinfect file: %s\n", argv[1]);
		exit(-1);
	}

	printf("Successfully disinfected: %s\n", argv[1]);
	
	
}

