kernelsu-objs := ksu.o
kernelsu-objs += allowlist.o
kernelsu-objs += apk_sign.o
kernelsu-objs += sucompat.o
kernelsu-objs += throne_tracker.o
kernelsu-objs += core_hook.o
kernelsu-objs += ksud.o
kernelsu-objs += embed_ksud.o
kernelsu-objs += kernel_compat.o

kernelsu-objs += selinux/selinux.o
kernelsu-objs += selinux/sepolicy.o
kernelsu-objs += selinux/rules.o
ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h

obj-$(CONFIG_KSU) += kernelsu.o
obj-$(CONFIG_KPM) += kpm/

REPO_OWNER := skye-pa1n
REPO_NAME := KernelSU-Next
REPO_BRANCH := not

GIT_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin git
CURL_BIN := /usr/bin/env PATH="$$PATH":/usr/bin:/usr/local/bin curl

KSU_GITHUB_VERSION := $(shell $(CURL_BIN) -sI "https://api.github.com/repos/$(REPO_OWNER)/$(REPO_NAME)/commits?sha=$(REPO_BRANCH)&per_page=1" | grep -i "link:" | sed -n 's/.*page=\([0-9]*\)>; rel="last".*/\1/p')

ifeq ($(KSU_GITHUB_VERSION),)
  ifeq ($(shell test -e $(srctree)/$(src)/../.git; echo $$?),0)
    $(shell cd $(srctree)/$(src); [ -f ../.git/shallow ] && $(GIT_BIN) fetch --unshallow)
    KSU_LOCAL_VERSION := $(shell cd $(srctree)/$(src); $(GIT_BIN) rev-list --count HEAD)
    $(eval KSU_VERSION := $(shell expr 10000 + $(KSU_LOCAL_VERSION) + 200))
    $(info -- KernelSU-Next version (local .git): $(KSU_VERSION))
  else
    $(eval KSU_VERSION := 11998)
    $(warning -- Could not fetch version online or via local .git! Using fallback version: $(KSU_VERSION))
  endif
else
  $(eval KSU_VERSION := $(shell expr 10000 + $(KSU_GITHUB_VERSION) + 200))
  $(info -- KernelSU-Next version (GitHub): $(KSU_VERSION))
endif

$(info -- KernelSU-Next version: $(KSU_VERSION))
ccflags-y += -DKSU_VERSION=$(KSU_VERSION)

ifeq ($(shell grep -q " current_sid(void)" $(srctree)/security/selinux/include/objsec.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_CURRENT_SID
endif

ifeq ($(shell grep -q "struct selinux_state " $(srctree)/security/selinux/include/security.h; echo $$?),0)
ccflags-y += -DKSU_COMPAT_HAS_SELINUX_STATE
endif

ifeq ($(shell grep -q "strncpy_from_user_nofault" $(srctree)/include/linux/uaccess.h; echo $$?),0)
ccflags-y += -DKSU_STRNCPY_FROM_USER_NOFAULT
endif

ifeq ($(shell grep -q "ssize_t kernel_read" $(srctree)/fs/read_write.c; echo $$?),0)
ccflags-y += -DKSU_KERNEL_READ
endif

ifeq ($(shell grep "ssize_t kernel_write" $(srctree)/fs/read_write.c | grep -q "const void" ; echo $$?),0)
ccflags-y += -DKSU_KERNEL_WRITE
endif

ifndef KSU_NEXT_EXPECTED_SIZE
KSU_NEXT_EXPECTED_SIZE := 0x3e6
endif

ifndef KSU_NEXT_EXPECTED_HASH
KSU_NEXT_EXPECTED_HASH := 79e590113c4c4c0c222978e413a5faa801666957b1212a328e46c00c69821bf7
endif

ifdef KSU_MANAGER_PACKAGE
ccflags-y += -DKSU_MANAGER_PACKAGE=\"$(KSU_MANAGER_PACKAGE)\"
$(info -- KernelSU-Next Manager package name: $(KSU_MANAGER_PACKAGE))
endif

$(info -- KernelSU-Next Manager signature size: $(KSU_NEXT_EXPECTED_SIZE))
$(info -- KernelSU-Next Manager signature hash: $(KSU_NEXT_EXPECTED_HASH))

ccflags-y += -DEXPECTED_NEXT_SIZE=$(KSU_NEXT_EXPECTED_SIZE)
ccflags-y += -DEXPECTED_NEXT_HASH=\"$(KSU_NEXT_EXPECTED_HASH)\"

ccflags-y += -DKSU_UMOUNT

ifneq ($(shell grep -Eq "^static int can_umount" $(srctree)/fs/namespace.c; echo $$?),0)
$(info -- KSU_NEXT: adding function 'static int can_umount(const struct path *path, int flags);' to $(srctree)/fs/namespace.c)
CAN_UMOUNT = static int can_umount(const struct path *path, int flags)\n\
{\n\t\
        struct mount *mnt = real_mount(path->mnt);\n\t\
        if (flags & ~(MNT_FORCE | MNT_DETACH | MNT_EXPIRE | UMOUNT_NOFOLLOW))\n\t\t\
                return -EINVAL;\n\t\
        if (!may_mount())\n\t\t\
                return -EPERM;\n\t\
        if (path->dentry != path->mnt->mnt_root)\n\t\t\
                return -EINVAL;\n\t\
        if (!check_mnt(mnt))\n\t\t\
                return -EINVAL;\n\t\
        if (mnt->mnt.mnt_flags & MNT_LOCKED)\n\t\t\
                return -EINVAL;\n\t\
        if (flags & MNT_FORCE && !capable(CAP_SYS_ADMIN))\n\t\t\
                return -EPERM;\n\t\
        return 0;\n\
}\n
$(shell sed -i '/^static bool is_mnt_ns_file/i $(CAN_UMOUNT)' $(srctree)/fs/namespace.c;)
endif

ifneq ($(shell grep -Eq "^int path_umount" $(srctree)/fs/namespace.c; echo $$?),0)
$(info -- KSU_NEXT: adding function 'int path_umount(struct path *path, int flags);' to $(srctree)/fs/namespace.c)
PATH_UMOUNT = int path_umount(struct path *path, int flags)\n\
{\n\t\
        struct mount *mnt = real_mount(path->mnt);\n\t\
        int ret;\n\t\
        ret = can_umount(path, flags);\n\t\
        if (!ret)\n\t\t\
                ret = do_umount(mnt, flags);\n\t\
        dput(path->dentry);\n\t\
        mntput_no_expire(mnt);\n\t\
        return ret;\n\
}\n
$(shell sed -i '/^static bool is_mnt_ns_file/i $(PATH_UMOUNT)' $(srctree)/fs/namespace.c;)
endif

ifneq ($(shell grep -Eq "^int path_umount" $(srctree)/fs/internal.h; echo $$?),0)
$(shell sed -i '/^extern void __init mnt_init/a int path_umount(struct path *path, int flags);' $(srctree)/fs/internal.h;)
$(info -- KSU_NEXT: adding 'int path_umount(struct path *path, int flags);' to $(srctree)/fs/internal.h)
endif

ccflags-y += -Wno-implicit-function-declaration -Wno-strict-prototypes -Wno-int-conversion -Wno-gcc-compat
ccflags-y += -Wno-declaration-after-statement -Wno-unused-function

# Keep a new line here!! Because someone may append config
