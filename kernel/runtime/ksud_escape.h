#ifndef __KSU_H_KSUD_ESCAPE
#define __KSU_H_KSUD_ESCAPE

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 2, 0) && !defined(CONFIG_KRETPROBES)
__attribute__((cold)) static noinline void sys_execve_escape_ksud(const char __user **filename_user);
__attribute__((cold)) static noinline void kernel_execve_escape_ksud(void *filename_ptr);
#else
static inline void sys_execve_escape_ksud(const char __user **filename_user) { } // no-op
static inline void kernel_execve_escape_ksud(void *filename_ptr) { } // no-op
#endif

static void ksud_escape_init();
static void ksud_escape_exit();

#endif
