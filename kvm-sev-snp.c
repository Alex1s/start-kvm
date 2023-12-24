#include <stdio.h> // printf
#include <fcntl.h> // open
#include <unistd.h> // close
#include <stdlib.h> // EXIT_FAILURE
#include <string.h> // strerrror
#include <errno.h> // errno
#include <sys/ioctl.h> // ioctl
#include <linux/kvm.h> // KVM_*
#include <sys/mman.h> // mmap
#include <stdint.h> // uintptr_t

#include "sev_snp_helper/sev_snp_helper.h"

#define KVM_DEV "/dev/kvm"
#define SEV_DEV "/dev/sev"

// the following is real mode assembly
#define GUEST_MEMORY_SIZE 4096
static uint8_t guest_code[GUEST_MEMORY_SIZE] __attribute__((aligned(GUEST_MEMORY_SIZE))) = {
    0xB8, 0xAA, 0xAA, // mov $0xAAAA, %ax
    0xF4 // hlt
};

#define perror_extra(message) do { if (message == NULL) fprintf(stderr, "%s:%d (%s): %s\n", __FILE__, __LINE__, __func__, strerror(errno)); else fprintf(stderr, "%s:%d (%s): %s\n", __FILE__, __LINE__, __func__, (const char *)message);} while (0)

#undef KVM_SET_MEMORY_ATTRIBUTES
#define KVM_SET_MEMORY_ATTRIBUTES              _IOW(KVMIO,  0xd3, struct kvm_memory_attributes) // source: /usr/src/linux-headers-6.6.0-rc1-snp-host-5a170ce1a082/include/uapi/linux/kvm.h:2379

#define KVM_X86_SW_PROTECTED_VM	1 // source: /mnt/data/AMDSEV-DOCKER/AMDSEV/linux/host/arch/x86/include/uapi/asm/kvm.h

#define DEFAULT_SEV_SNP_POLICY  0x30000 // source: /mnt/data/AMDSEV-DOCKER/AMDSEV/qemu/target/i386/sev.c

int main()
{
    int sev_snp_helper_fd = -1;
    int kvm_fd = -1;
    int error = 0;
    int ret = 0;
    void *ret_ptr = NULL;
    int vm_fd = -1;
    int vcpu_mmap_size = 0;
    struct kvm_run *kvm_run = NULL;
    struct kvm_memory_attributes kvm_memory_attributes = {0};
    struct kvm_create_guest_memfd kvm_create_guest_memfd = {0};
    struct kvm_userspace_memory_region2 kvm_userspace_memory_region2 = {0};
    int vcpu_fd = -1;
    struct kvm_regs kvm_regs = {.rip = 0};
	struct kvm_sregs kvm_sregs = {0};

    int sev_fd = -1;
    struct kvm_sev_cmd kvm_sev_cmd = {0};
    struct kvm_snp_init kvm_snp_init = {0};
    struct kvm_sev_snp_launch_start kvm_sev_snp_launch_start = {0};
    struct kvm_sev_snp_launch_update kvm_sev_snp_launch_update = {0};

    sev_snp_helper_fd = open(SEV_SNP_HELPER_DEV, O_RDONLY | O_CLOEXEC);
    if (sev_snp_helper_fd == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_null;
    }

    kvm_fd = open(KVM_DEV, O_RDONLY | O_CLOEXEC);
    if (kvm_fd == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_open_sev_snp_helper;
    }

    // possible machine type identifiers for x86:
    // #define KVM_X86_DEFAULT_VM	0
    // #define KVM_X86_SW_PROTECTED_VM	1
    // #define KVM_X86_SNP_VM		3
    // NOTE how KVM_X86_SNP_VM implies KVM_X86_SW_PROTECTED_VM
    // source: /mnt/data/AMDSEV-DOCKER/AMDSEV/linux/host/arch/x86/include/uapi/asm/kvm.h
    ret = ioctl(kvm_fd, KVM_CREATE_VM, KVM_X86_SNP_VM);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_open_kvm;
    }
    vm_fd = ret;

    // possible memory attributes:
    // #define KVM_MEMORY_ATTRIBUTE_PRIVATE           (1ULL << 3)
    // source: /mnt/data/AMDSEV-DOCKER/AMDSEV/qemu/linux-headers/linux/kvm.h
    kvm_memory_attributes.address = 0;
    kvm_memory_attributes.size = GUEST_MEMORY_SIZE;
    kvm_memory_attributes.attributes = KVM_MEMORY_ATTRIBUTE_PRIVATE;
    ret = ioctl(vm_fd, KVM_SET_MEMORY_ATTRIBUTES, &kvm_memory_attributes);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vm;
    }

    // possible flags:
    // #define KVM_GUEST_MEMFD_ALLOW_HUGEPAGE		(1ULL << 0)
    // NOTE that no flag i.e. "0" is allowed as well
    // source: /mnt/data/AMDSEV-DOCKER/AMDSEV/linux/host/include/uapi/linux/kvm.h
    kvm_create_guest_memfd.size = GUEST_MEMORY_SIZE;
    kvm_create_guest_memfd.flags = 0;
    ret = ioctl(vm_fd, KVM_CREATE_GUEST_MEMFD, &kvm_create_guest_memfd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vm;
    }
    int guest_memfd = ret;

    // possible flags:
    // #define KVM_MEM_LOG_DIRTY_PAGES	(1UL << 0)
    // #define KVM_MEM_READONLY	(1UL << 1)
    // #define KVM_MEM_PRIVATE		(1UL << 2)
    // source: /mnt/data/AMDSEV-DOCKER/AMDSEV/linux/host/include/uapi/linux/kvm.h
    kvm_userspace_memory_region2.guest_phys_addr = 0x0;
    kvm_userspace_memory_region2.memory_size = GUEST_MEMORY_SIZE;
    kvm_userspace_memory_region2.userspace_addr = (uintptr_t) guest_code;
    kvm_userspace_memory_region2.gmem_offset = 0;
    kvm_userspace_memory_region2.gmem_fd = guest_memfd;
    kvm_userspace_memory_region2.flags = KVM_MEM_PRIVATE;
    kvm_userspace_memory_region2.slot = 0;
    ret = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION2, &kvm_userspace_memory_region2);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_guest_memfd;
    }

    sev_fd = open(SEV_DEV, O_RDONLY | O_CLOEXEC);
    if (sev_fd == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_guest_memfd;
    }

    // NOTE that KVM_SEV_SNP_INIT has to be issued before creating a vcpu
    kvm_sev_cmd.id = KVM_SEV_SNP_INIT;
    kvm_sev_cmd.sev_fd = sev_fd;
    kvm_sev_cmd.data = (__u64) &kvm_snp_init;
    ret = ioctl(vm_fd, KVM_MEMORY_ENCRYPT_OP, &kvm_sev_cmd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_open_sev;
    }
    if (kvm_sev_cmd.error)
    {
        perror_extra("SEV error");
        error = 1;
        goto error_after_open_sev;
    }

    ret = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_open_sev;
    }
    vcpu_fd = ret;

    ret = ioctl(vcpu_fd, KVM_SET_REGS, &kvm_regs);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vcpu;
    }

    ret = ioctl(vcpu_fd, KVM_GET_SREGS, &kvm_sregs);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vcpu;
    }
    kvm_sregs.cs.base = 0;
    kvm_sregs.cs.limit = 0xFFFF;
    ret = ioctl(vcpu_fd, KVM_SET_SREGS, &kvm_sregs);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vcpu;
    }

    ret = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vcpu;
    }
    vcpu_mmap_size = ret;

    ret_ptr = mmap(NULL, vcpu_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
    if (ret_ptr == MAP_FAILED)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vcpu;
    }
    kvm_run = ret_ptr;

    kvm_sev_cmd.id = KVM_SEV_SNP_LAUNCH_START;
    kvm_sev_cmd.data = (__u64) &kvm_sev_snp_launch_start;
    kvm_sev_cmd.sev_fd = sev_fd;
    kvm_sev_snp_launch_start.policy = DEFAULT_SEV_SNP_POLICY;
    ret = ioctl(vm_fd, KVM_MEMORY_ENCRYPT_OP, &kvm_sev_cmd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_vcpu;
    }
    if (kvm_sev_cmd.error != 0)
    {
        perror_extra("SEV error");
        error = 1;
        goto error_after_mmap_vcpu;
    }

    // possible page types:
    // #define KVM_SEV_SNP_PAGE_TYPE_NORMAL		0x1
    // #define KVM_SEV_SNP_PAGE_TYPE_VMSA		0x2
    // #define KVM_SEV_SNP_PAGE_TYPE_ZERO		0x3
    // #define KVM_SEV_SNP_PAGE_TYPE_UNMEASURED	0x4
    // #define KVM_SEV_SNP_PAGE_TYPE_SECRETS		0x5
    // #define KVM_SEV_SNP_PAGE_TYPE_CPUID		0x6
    // source: /mnt/data/AMDSEV-DOCKER/AMDSEV/linux/host/include/uapi/linux/kvm.h
    kvm_sev_cmd.id = KVM_SEV_SNP_LAUNCH_UPDATE;
    kvm_sev_cmd.data = (__u64) &kvm_sev_snp_launch_update;
    kvm_sev_cmd.sev_fd = sev_fd;
    kvm_sev_snp_launch_update.start_gfn = 0;
    kvm_sev_snp_launch_update.uaddr = (__u64) guest_code;
    kvm_sev_snp_launch_update.len = GUEST_MEMORY_SIZE;
    kvm_sev_snp_launch_update.page_type = KVM_SEV_SNP_PAGE_TYPE_NORMAL;
    ret = ioctl(vm_fd, KVM_MEMORY_ENCRYPT_OP, &kvm_sev_cmd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_vcpu;
    }
    if (kvm_sev_cmd.error != 0)
    {
        perror_extra("SEV error");
        error = 1;
        goto error_after_mmap_vcpu;
    }

    kvm_sev_cmd.id = KVM_SEV_SNP_LAUNCH_FINISH;
    kvm_sev_cmd.sev_fd = sev_fd;
    ret = ioctl(vm_fd, KVM_MEMORY_ENCRYPT_OP, &kvm_sev_cmd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_vcpu;
    }
    if (kvm_sev_cmd.error != 0)
    {
        perror_extra("SEV error");
        error = 1;
        goto error_after_mmap_vcpu;
    }

    // before we start the VM, lets get the physical address of our ONLY VM page
    struct sev_snp_helper_get_phys_addr sev_snp_helper_get_phys_addr = { // TODO: move up to declarations ...
        .kvm_fd = kvm_fd,
        .slot = kvm_userspace_memory_region2.slot,
        .phys_addr = 0 // output
    };
    ret = ioctl(sev_snp_helper_fd, SEV_SNP_HELPER_GET_PHYS_ADDR, sev_snp_helper_get_phys_addr);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_vcpu;
    }
    printf("VM physical address: %llx\n", sev_snp_helper_get_phys_addr.phys_addr);

    ret = ioctl(vcpu_fd, KVM_RUN, 0);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_vcpu;
    }
    sleep(1); // let the vm execute

    if (kvm_run->exit_reason != KVM_EXIT_HLT)
    {
        printf("kvm_run->exit_reason=%d\n", kvm_run->exit_reason);
        perror_extra("VM did not exit for reason KVM_EXIT_HLT");
        error = 1;
        if (kvm_run->exit_reason == KVM_EXIT_FAIL_ENTRY)
        {
            printf("kvm_run->fail_entry.hardware_entry_failure_reason=%lld\n", kvm_run->fail_entry.hardware_entry_failure_reason);
            printf("kvm_run->fail_entry.cpu=%d\n", kvm_run->fail_entry.cpu);
        }
        goto error_after_mmap_vcpu;
    }

    ret = ioctl(vcpu_fd, KVM_GET_REGS, &kvm_regs);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_vcpu;
    }

    if (kvm_regs.rax != 0xAAAA)
    {
        printf("kvm_regs.rax=%llx\n", kvm_regs.rax);
        perror_extra("kvm_regs.rax!=0xAAAA\n");
        error = 1;
        goto error_after_mmap_vcpu;
    }
    if (kvm_regs.rip != 0x4)
    {
        printf("kvm_regs.rip=%llx\n", kvm_regs.rip);
        perror_extra("kvm_regs.rip!=0x4\n");
        error = 1;
        goto error_after_mmap_vcpu;
    }

    printf("All OK SEV-SNP.\n");

    error_after_mmap_vcpu:
    munmap(kvm_run, vcpu_mmap_size);

    error_after_kvm_create_vcpu:
    if (close(vcpu_fd) == -1)
    {
        perror_extra(NULL);
    }

    error_after_open_sev:
    if (close(sev_fd) == -1)
    {
        perror_extra(NULL);
    }

    error_after_guest_memfd:
    if (close(guest_memfd) == -1)
    {
        perror_extra(NULL);
    }

    error_after_kvm_create_vm:
    if (close(vm_fd) == -1)
    {
        perror_extra(NULL);
    }

    error_after_open_kvm:
    if (close(kvm_fd) == -1)
    {
        perror_extra(NULL);
    }

    error_after_open_sev_snp_helper:
    if (close(sev_snp_helper_fd) == -1)
    {
        perror_extra(NULL);
    }

    error_after_null:
    if (error)
    {
        return EXIT_FAILURE;
    }
    else
    {
        return EXIT_SUCCESS;
    }
}