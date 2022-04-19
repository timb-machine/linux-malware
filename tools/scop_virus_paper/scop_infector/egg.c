
/*
 * infect.c will patch these values
 * with the addrs of e_entry, and get_rip()
 * from before they are relocated at runtime.
 * These are then subtracted from eachother and
 * from the instruction pointer to get the correct
 * address to jump to.
 */
static unsigned long o_entry __attribute__((section(".data"))) = {0x00};
static unsigned long vaddr_of_get_rip __attribute__((section(".data"))) = {0x00};

unsigned long get_rip(void);

extern long get_rip_label;
extern long real_start;

#define __ASM__ asm volatile
/*
 * Code to jump back to entry point
 */
int volatile _start() {
	unsigned long n_entry = get_rip() - (vaddr_of_get_rip - o_entry);

	__asm__ volatile (
		"movq %0, %%rbx\n"
		"jmpq *%0" :: "g"(n_entry)
		);
}

/*
 * All of your parasite code would typically go between
 * _start() and get_rip(). Currently the parasite simply
 * calculates the address of the original entry point
 * (Since we are being injected into a PIE executable)
 * and jumps there.
 */
unsigned long get_rip(void)
{
	long ret;
	__asm__ __volatile__
	(
	"call get_rip_label	\n"
	".globl get_rip_label	\n"
	"get_rip_label:		\n"
	"pop %%rax		\n"
	"mov %%rax, %0" : "=r"(ret)
	);

	return ret;
}
