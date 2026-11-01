/* Diagnostic-only probe re-entry fixture for the isolated Linux 6.8 VM.
 * No syscall redirection, persistent changes, or directory record rewriting.
 */
#include <linux/atomic.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Explicit kprobe re-entry fault injection for measurement validation");

/* Linux v6.8 fs/readdir.c layout, used only on the locked 6.8 research VM. */
struct diagnostic_callback64 {
    struct dir_context ctx;
    struct linux_dirent64 __user *current_dir;
    int prev_reclen;
    int count;
    int error;
};
static bool (*observed_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);
static atomic64_t injected=ATOMIC64_INIT(0);
static bool ready;
static unsigned int trigger;

static noinline unsigned long completion_fault_anchor(void)
{
    return READ_ONCE(jiffies);
}

static int reenter(struct kprobe *probe, struct pt_regs *regs)
{
    struct diagnostic_callback64 buffer={};
    /* An invalid zero-length name returns before any userspace write.
     * Running while the anchor kprobe is active exercises the kernel's
     * real probe re-entry/miss path, not a fabricated profile value.
     */
    observed_filldir(&buffer.ctx,"",0,0,0,DT_UNKNOWN);
    atomic64_inc(&injected);
    return 0;
}
static struct kprobe anchor_probe={
    .addr=(kprobe_opcode_t *)completion_fault_anchor,
    .pre_handler=reenter,
};

static int set_trigger(const char *value,const struct kernel_param *parameter)
{
    unsigned int count,i;
    int error=kstrtouint(value,0,&count);
    if (error || count>1024)return -EINVAL;
    if (count && !ready)return -EAGAIN;
    trigger=count;
    for (i=0;i<count;i++)completion_fault_anchor();
    return 0;
}
static int get_injected(char *buffer,const struct kernel_param *parameter)
{
    return sysfs_emit(buffer,"%lld\n",(long long)atomic64_read(&injected));
}
static const struct kernel_param_ops trigger_ops={.set=set_trigger,.get=param_get_uint};
static const struct kernel_param_ops injected_ops={.get=get_injected};
module_param_cb(trigger,&trigger_ops,&trigger,0644);
module_param_cb(injected,&injected_ops,NULL,0444);

static int __init diagnostic_init(void)
{
    struct kprobe lookup={.symbol_name="filldir64"};
    int error=register_kprobe(&lookup);
    if(error)return error;
    observed_filldir=(void *)lookup.addr;
    unregister_kprobe(&lookup);
    error=register_kprobe(&anchor_probe);
    if(error)return error;
    ready=true;
    return 0;
}
static void __exit diagnostic_exit(void)
{
    ready=false;
    unregister_kprobe(&anchor_probe);
}
module_init(diagnostic_init);
module_exit(diagnostic_exit);
