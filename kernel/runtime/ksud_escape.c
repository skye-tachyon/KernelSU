#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
__attribute__((cold))
static noinline void sys_execve_escape_ksud(const char __user **filename_user)
{
	// see if its init
	if (!is_init(current_cred()))
		return;

	const char ksud_path[] = KSUD_PATH;
	char path[sizeof(ksud_path)];

	// see if its trying to execute ksud
	if (ksu_copy_from_user_retry(path, *filename_user, sizeof(path)))
		return;

	if (memcmp(ksud_path, path, sizeof(path)))
		return;

	pr_info("sys_execve: escape init executing %s with pid: %d\n", path, current->pid);

	escape_to_root_forced(); // give this context all permissions
	
	return;
}

__attribute__((cold))
static noinline void kernel_execve_escape_ksud(void *filename_ptr)
{
	// see if its init
	if (!is_init(current_cred()))
		return;

	if (likely(memcmp(filename_ptr, KSUD_PATH, sizeof(KSUD_PATH))))
		return;

	pr_info("kernel_execve: escape init executing %s with pid: %d\n", filename_ptr, current->pid);

	escape_to_root_forced(); // give this context all permissions
	
	return;
}
#endif

// UL bprm_set_creds handling
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
static int bprm_set_creds_restore(void *data);
static int (*orig_bprm_set_creds)(struct linux_binprm *bprm) = NULL;
static int hook_bprm_set_creds(struct linux_binprm *bprm)
{
	if (likely(ksu_boot_completed))
		goto bprm_set_creds;

	if (!is_init(current_cred()))
		goto bprm_set_creds;

	if (!bprm->filename)
		goto bprm_set_creds;

	if (!!strcmp(bprm->filename, "/data/adb/ksud"))
		goto bprm_set_creds;

	pr_info("bprm_set_creds: allow init executing %s with pid: %d\n", bprm->filename, current->pid);
	return 0;

bprm_set_creds:
	return orig_bprm_set_creds(bprm);
}

static int bprm_set_creds_restore(void *data)
{
	static bool ran_once = false;

	if (ran_once)
		return 0;

	ran_once = true;

	msleep(1000);
	
	struct security_operations *ops = (struct security_operations *)selinux_ops_addr;

	if (!ops)
		return 0;

	if (!!strcmp((char *)ops, "selinux"))
		return 0;

	pr_info("%s: selinux_ops: 0x%lx .name = %s\n", __func__, (long)ops, (const char *)ops );

	preempt_disable();
	local_irq_disable();

	if (orig_bprm_set_creds) {
		pr_info("%s: restoring: 0x%lx to 0x%lx\n", __func__, (long)ops->bprm_set_creds, (long)orig_bprm_set_creds);
		ops->bprm_set_creds = orig_bprm_set_creds;
	}

	smp_mb();

	local_irq_enable();
	preempt_enable();
	return 0;
}
#endif

static void ksud_escape_init() { }

static void ksud_escape_exit()
{
	static bool already_ran = false;
	if (already_ran)
		return;

	already_ran = true;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 2, 0)
	kthread_run(bprm_set_creds_restore, NULL, "unhook");
#endif
}

