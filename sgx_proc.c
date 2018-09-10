#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>   
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include "sgx.h"
#define BUFSIZE  4096

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Bhushan Jain");


static struct proc_dir_entry *sgx;
static struct proc_dir_entry *counters;
static struct proc_dir_entry *sgx_exits;
static struct proc_dir_entry *sgx_enter;
static struct proc_dir_entry *sgx_page_faults;
static struct proc_dir_entry *epc_misses;
static struct proc_dir_entry *invalidate_events;
static struct proc_dir_entry *flush_cpus;
static struct proc_dir_entry *pages_added;
static struct proc_dir_entry *pages_removed;
static struct proc_dir_entry *pages_evicted;
static struct proc_dir_entry *pages_blocked;
static struct proc_dir_entry *pages_dirty;
static struct proc_dir_entry *pages_load_blocked;
static struct proc_dir_entry *pages_load_unlocked;
static struct proc_dir_entry *block_check_activated;


static ssize_t sgx_proc_write_sgx_exits(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->sgx_exits = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_sgx_exits(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.sgx_exits); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->sgx_exits);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}

static ssize_t sgx_proc_write_sgx_enter(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->sgx_enter = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_sgx_enter(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.sgx_enter); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->sgx_enter);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_sgx_page_faults(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->sgx_page_faults = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_sgx_page_faults(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.sgx_page_faults); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->sgx_page_faults);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_epc_misses(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->epc_misses = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_epc_misses(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.epc_misses); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->epc_misses);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_invalidate_events(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->invalidate_events = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_invalidate_events(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.invalidate_events); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->invalidate_events);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_flush_cpus(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->flush_cpus = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_flush_cpus(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.flush_cpus); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->flush_cpus);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_pages_added(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->pages_added = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_pages_added(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.pages_added); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->pages_added);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_pages_removed(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->pages_removed = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_pages_removed(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.pages_removed); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->pages_removed);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_pages_evicted(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->pages_evicted = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_pages_evicted(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.pages_evicted); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->pages_evicted);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_pages_blocked(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->pages_blocked = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_pages_blocked(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.pages_blocked); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->pages_blocked);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_pages_dirty(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->pages_dirty = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_pages_dirty(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.pages_dirty); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->pages_dirty);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_pages_load_blocked(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->pages_load_blocked = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_pages_load_blocked(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.pages_load_blocked); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->pages_load_blocked);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_pages_load_unlocked(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->pages_load_unlocked = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_pages_load_unlocked(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.pages_load_unlocked); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->pages_load_unlocked);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static ssize_t sgx_proc_write_block_check_activated(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
	u64 pgd, val;
	char *buf;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	int num, c;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);	

	if(*ppos > 0 || count > BUFSIZE)
		return -EFAULT;
	if(copy_from_user(buf,ubuf,count))
		return -EFAULT;
	num = sscanf(buf,"%llu %llu", &pgd, &val);
	if(num != 1)
		return -EFAULT;

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			if(pgd_val(*(encl->mm->pgd)) == pgd)
				encl->encl_stats->block_check_activated = val;
	}

	c = strlen(buf);
	*ppos = c;
	return c;
}

static ssize_t sgx_proc_read_block_check_activated(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
	char *buf;
	int len=0;
	struct sgx_tgid_ctx *ctx;
	struct sgx_encl *encl;
	buf = (char*)kmalloc(BUFSIZE, GFP_KERNEL);

	if(*ppos > 0 || count < BUFSIZE)
		return 0;

	len += sprintf(buf+len,"Global: %llu\n", global_stats.block_check_activated); 
	len += sprintf(buf+len,"Enc ID \t Value\n");

	list_for_each_entry(ctx, &sgx_tgid_ctx_list, list) {
		list_for_each_entry(encl, &(ctx->encl_list), encl_list)
			len += sprintf(buf+len,"%lx \t %llu\n", pgd_val(*(encl->mm->pgd)), encl->encl_stats->block_check_activated);
	}

	if(copy_to_user(ubuf,buf,len))
		return -EFAULT;
	*ppos = len;
	return len;
}


static struct file_operations sgx_exits_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_sgx_exits,
	.write = sgx_proc_write_sgx_exits,
};

static struct file_operations sgx_enter_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_sgx_enter,
	.write = sgx_proc_write_sgx_enter,
};


static struct file_operations sgx_page_faults_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_sgx_page_faults,
	.write = sgx_proc_write_sgx_page_faults,
};


static struct file_operations epc_misses_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_epc_misses,
	.write = sgx_proc_write_epc_misses,
};


static struct file_operations invalidate_events_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_invalidate_events,
	.write = sgx_proc_write_invalidate_events,
};


static struct file_operations flush_cpus_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_flush_cpus,
	.write = sgx_proc_write_flush_cpus,
};


static struct file_operations pages_added_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_pages_added,
	.write = sgx_proc_write_pages_added,
};


static struct file_operations pages_removed_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_pages_removed,
	.write = sgx_proc_write_pages_removed,
};


static struct file_operations pages_evicted_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_pages_evicted,
	.write = sgx_proc_write_pages_evicted,
};


static struct file_operations pages_blocked_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_pages_blocked,
	.write = sgx_proc_write_pages_blocked,
};


static struct file_operations pages_dirty_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_pages_dirty,
	.write = sgx_proc_write_pages_dirty,
};


static struct file_operations pages_load_blocked_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_pages_load_blocked,
	.write = sgx_proc_write_pages_load_blocked,
};


static struct file_operations pages_load_unlocked_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_pages_load_unlocked,
	.write = sgx_proc_write_pages_load_unlocked,
};


static struct file_operations block_check_activated_ops = 
{
	.owner = THIS_MODULE,
	.read = sgx_proc_read_block_check_activated,
	.write = sgx_proc_write_block_check_activated,
};


static int sgx_proc_init(void)
{
	sgx = proc_mkdir_mode("sgx", 0777, NULL);
	counters = proc_mkdir_mode("counters", 0777, sgx);


	sgx_exits = proc_create("sgx_exits", 0666, counters, &sgx_exits_ops);
	sgx_enter = proc_create("sgx_enter", 0666, counters, &sgx_enter_ops);
	sgx_page_faults = proc_create("sgx_page_faults", 0666, counters, &sgx_page_faults_ops);
	epc_misses = proc_create("epc_misses", 0666, counters, &epc_misses_ops);
	invalidate_events = proc_create("invalidate_events", 0666, counters, &invalidate_events_ops);
	flush_cpus = proc_create("flush_cpus", 0666, counters, &flush_cpus_ops);
	pages_added = proc_create("pages_added", 0666, counters, &pages_added_ops);
	pages_removed = proc_create("pages_removed", 0666, counters, &pages_removed_ops);
	pages_evicted = proc_create("pages_evicted", 0666, counters, &pages_evicted_ops);
	pages_blocked = proc_create("pages_blocked", 0666, counters, &pages_blocked_ops);
	pages_dirty = proc_create("pages_dirty", 0666, counters, &pages_dirty_ops);
	pages_load_blocked = proc_create("pages_load_blocked", 0666, counters, &pages_load_blocked_ops);
	pages_load_unlocked = proc_create("pages_load_unlocked", 0666, counters, &pages_load_unlocked_ops);
	block_check_activated = proc_create("block_check_activated", 0666, counters, &block_check_activated_ops);

	printk(KERN_ALERT "hello...\n");
	return 0;
}

static void sgx_proc_cleanup(void)
{

	proc_remove(sgx_exits);
	proc_remove(sgx_enter);
	proc_remove(sgx_page_faults);
	proc_remove(epc_misses);
	proc_remove(invalidate_events);
	proc_remove(flush_cpus);
	proc_remove(pages_added);
	proc_remove(pages_removed);
	proc_remove(pages_evicted);
	proc_remove(pages_blocked);
	proc_remove(pages_dirty);
	proc_remove(pages_load_blocked);
	proc_remove(pages_load_unlocked);
	proc_remove(block_check_activated);
	proc_remove(counters);
	proc_remove(sgx);

	remove_proc_subtree("sgx", NULL);
	printk(KERN_WARNING "bye ...\n");
}

module_init(sgx_proc_init);
module_exit(sgx_proc_cleanup);
