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

#define KVM_DEV "/dev/kvm"
#define SEV_DEV "/dev/sev"
#define GUEST_MEMORY_SIZE 4096

#define MAX_MEASUREMENT_LEN 4096

// the following is real mode assembly
static uint8_t guest_code[GUEST_MEMORY_SIZE] __attribute__((aligned(GUEST_MEMORY_SIZE))) = {
    0xB8, 0xAA, 0xAA, // mov $0xAAAA, %ax
    0xF4 // hlt
};

#define perror_extra(message) do { if (message == NULL) fprintf(stderr, "%s:%d (%s): %s\n", __FILE__, __LINE__, __func__, strerror(errno)); else fprintf(stderr, "%s:%d (%s): %s\n", __FILE__, __LINE__, __func__, (const char *)message);} while (0)


// src: /usr/src/linux-headers-6.6.0-rc1-snp-host-5a170ce1a082/include/uapi/linux/kvm.h:2379
#undef KVM_SET_MEMORY_ATTRIBUTES
#define KVM_SET_MEMORY_ATTRIBUTES              _IOW(KVMIO,  0xd3, struct kvm_memory_attributes)

#define KVM_X86_SW_PROTECTED_VM	1

int main()
{
    int kvm_fd = -1;
    int error = 0;
    int ret = 0;
    void *ret_ptr = NULL;
    void *guest_memory = NULL;
    size_t guest_memory_size = 0;
    int vm_fd = -1;
    int vcpu_mmap_size = 0;
    struct kvm_run *kvm_run = NULL;
    struct kvm_userspace_memory_region2 kvm_userspace_memory_region2 = {0};
    int vcpu_fd = -1;
    struct kvm_regs kvm_regs = {.rip = 0};
	struct kvm_sregs kvm_sregs = {0};

    int sev_fd = -1;
    uint64_t supported_memory_attributes = -1;
    struct kvm_sev_cmd kvm_sev_cmd = {0};
    struct kvm_snp_init kvm_snp_init = {0};
    struct kvm_sev_snp_launch_start kvm_sev_snp_launch_start = {0};
    struct kvm_sev_snp_launch_update kvm_sev_snp_launch_update = {0};
    struct kvm_sev_launch_measure kvm_sev_launch_measure = {0};
    uint8_t measurement[MAX_MEASUREMENT_LEN];
    struct kvm_sev_guest_status kvm_sev_guest_status = {0};

    kvm_fd = open(KVM_DEV, O_RDONLY | O_CLOEXEC);
    if (kvm_fd == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_null;
    }

    // possible machine type identifiers for x86:
    // #define KVM_X86_DEFAULT_VM	0
    // #define KVM_X86_SW_PROTECTED_VM	1
    // #define KVM_X86_SNP_VM		3
    // NOTE how KVM_X86_SNP_VM implies KVM_X86_SW_PROTECTED_VM
    ret = ioctl(kvm_fd, KVM_CREATE_VM, KVM_X86_SNP_VM);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_guest_memory;
    }
    vm_fd = ret;

    guest_memory_size = GUEST_MEMORY_SIZE;
    ret_ptr = mmap(NULL, guest_memory_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (ret_ptr == MAP_FAILED)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_open_kvm;
    }
    memcpy((void *__restrict) ret_ptr, (void *__restrict) guest_code, sizeof(guest_code));
    //guest_memory = ret_ptr;
    guest_memory = guest_code;

    ret = ioctl(vm_fd, KVM_GET_SUPPORTED_MEMORY_ATTRIBUTES, &supported_memory_attributes);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vm;
    }
    printf("KVM_GET_SUPPORTED_MEMORY_ATTRIBUTES: %lu (KVM_MEMORY_ATTRIBUTE_PRIVATE: %llu)\n", supported_memory_attributes, KVM_MEMORY_ATTRIBUTE_PRIVATE);
    if (!(supported_memory_attributes & KVM_MEMORY_ATTRIBUTE_PRIVATE))
    {
        perror_extra("VM does not support KVM_MEMORY_ATTRIBUTE_PRIVATE");
        error = 1;
        goto error_after_kvm_create_vm;
    }

    struct kvm_memory_attributes kvm_memory_attributes = {
        .address = 0,
        .size = guest_memory_size,
        .attributes = KVM_MEMORY_ATTRIBUTE_PRIVATE
    };
    ret = ioctl(vm_fd, KVM_SET_MEMORY_ATTRIBUTES, &kvm_memory_attributes);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vm;
    }

    struct kvm_create_guest_memfd kvm_create_guest_memfd = {.size = guest_memory_size, .flags = 0}; // possible flags: 0, KVM_GUEST_MEMFD_ALLOW_HUGEPAGE
    ret = ioctl(vm_fd, KVM_CREATE_GUEST_MEMFD, &kvm_create_guest_memfd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_guest_memory;
    }
    int guest_memfd = ret;

    kvm_userspace_memory_region2.guest_phys_addr = 0x0;
    kvm_userspace_memory_region2.memory_size = guest_memory_size;
    kvm_userspace_memory_region2.userspace_addr = (uintptr_t) guest_memory;
    kvm_userspace_memory_region2.gmem_offset = 0;
    kvm_userspace_memory_region2.gmem_fd = guest_memfd;
    // possible flags: KVM_MEM_LOG_DIRTY_PAGES = 1, KVM_MEM_READONLY = 2 and KVM_MEM_PRIVATE = 4
    kvm_userspace_memory_region2.flags = KVM_MEM_PRIVATE | KVM_MEM_READONLY; // this is what QEMU uses for page type NORMAL
    kvm_userspace_memory_region2.slot = 0;
    printf("KVM_SET_USER_MEMORY_REGION2=0x%lx\n", KVM_SET_USER_MEMORY_REGION2);
    ret = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION2, &kvm_userspace_memory_region2);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vm;
    }

    sev_fd = open(SEV_DEV, O_RDONLY | O_CLOEXEC);
    if (sev_fd == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vm;
    }

    // has to be issued before creating a vcpu
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
        goto error_after_kvm_create_vcpu; // TODO
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
    //kvm_sev_snp_launch_start.policy = (1 << 17) | (1 << 19) | (1 << 16);
    kvm_sev_snp_launch_start.policy = (1 << 17) | (1 << 16); // this is the same as qemu uses
    printf("kvm_sev_snp_launch_start policy 0x%llx\n", kvm_sev_snp_launch_start.policy);
    ret = ioctl(vm_fd, KVM_MEMORY_ENCRYPT_OP, &kvm_sev_cmd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vcpu;
    }
    if (kvm_sev_cmd.error != 0)
    {
        perror_extra("SEV error");
        error = 1;
        goto error_after_kvm_create_vcpu;
    }

    kvm_sev_cmd.id = KVM_SEV_SNP_LAUNCH_UPDATE;
    kvm_sev_cmd.data = (__u64) &kvm_sev_snp_launch_update;
    kvm_sev_cmd.sev_fd = sev_fd;
    kvm_sev_snp_launch_update.start_gfn = 0;
    kvm_sev_snp_launch_update.uaddr = (__u64) guest_memory;
    kvm_sev_snp_launch_update.len = guest_memory_size;
    kvm_sev_snp_launch_update.page_type = KVM_SEV_SNP_PAGE_TYPE_NORMAL;
    ret = ioctl(vm_fd, KVM_MEMORY_ENCRYPT_OP, &kvm_sev_cmd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vcpu;
    }
    if (kvm_sev_cmd.error != 0)
    {
        perror_extra("SEV error");
        error = 1;
        goto error_after_kvm_create_vcpu;
    }

    kvm_sev_cmd.id = KVM_SEV_LAUNCH_UPDATE_VMSA;
    kvm_sev_cmd.data = 0;
    //ret = ioctl(vm_fd, KVM_MEMORY_ENCRYPT_OP, &kvm_sev_cmd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vcpu;
    }
    if (kvm_sev_cmd.error != 0)
    {
        perror_extra("SEV error");
        error = 1;
        goto error_after_kvm_create_vcpu;
    }

    kvm_sev_cmd.id = KVM_SEV_LAUNCH_MEASURE;
    kvm_sev_cmd.data = (__u64) &kvm_sev_launch_measure;
    kvm_sev_cmd.sev_fd = sev_fd;
    kvm_sev_launch_measure.uaddr = (__u64) measurement;
    kvm_sev_launch_measure.len = MAX_MEASUREMENT_LEN;
    //ret = ioctl(vm_fd, KVM_MEMORY_ENCRYPT_OP, &kvm_sev_cmd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vcpu;
    }
    if (kvm_sev_cmd.error != 0)
    {
        perror_extra("SEV error");
        error = 1;
        goto error_after_kvm_create_vcpu;
    }
    if (kvm_sev_launch_measure.len > MAX_MEASUREMENT_LEN)
    {
        perror_extra("MAX_MEASUREMENT_LEN is too small");
        error = 1;
        goto error_after_kvm_create_vcpu;
    }

    kvm_sev_cmd.id = KVM_SEV_SNP_LAUNCH_FINISH;
    kvm_sev_cmd.sev_fd = sev_fd;
    ret = ioctl(vm_fd, KVM_MEMORY_ENCRYPT_OP, &kvm_sev_cmd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vcpu;
    }
    if (kvm_sev_cmd.error != 0)
    {
        perror_extra("SEV error");
        error = 1;
        goto error_after_kvm_create_vcpu;
    }

    kvm_sev_cmd.id = KVM_SEV_GUEST_STATUS;
    kvm_sev_cmd.data = (__u64) &kvm_sev_guest_status;
    ret = ioctl(vm_fd, KVM_MEMORY_ENCRYPT_OP, &kvm_sev_cmd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_create_vcpu;
    }
    if (kvm_sev_cmd.error != 0)
    {
        perror_extra("SEV error");
        error = 1;
        goto error_after_kvm_create_vcpu;
    }
    printf("Guest state: %d\n", kvm_sev_guest_status.state);

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
        goto error_after_kvm_run;
    }

    ret = ioctl(vcpu_fd, KVM_GET_REGS, &kvm_regs);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_kvm_run;
    }

    if (kvm_regs.rax != 0xAAAA)
    {
        printf("kvm_regs.rax=%llx\n", kvm_regs.rax);
        perror_extra("kvm_regs.rax!=0xAAAA\n");
        error = 1;
        goto error_after_kvm_run;
    }
    if (kvm_regs.rip != 0x4)
    {
        printf("kvm_regs.rip=%llx\n", kvm_regs.rip);
        perror_extra("kvm_regs.rip!=0x4\n");
        error = 1;
        goto error_after_kvm_run;
    }

    printf("All OK SEV.\n");

    error_after_kvm_run:
    munmap(kvm_run, vcpu_mmap_size);

    error_after_mmap_vcpu:
    if (close(vcpu_fd) == -1)
    {
        perror_extra(NULL);
    }

    error_after_kvm_create_vcpu:
    close(vcpu_fd);

    error_after_kvm_create_vm:
    if (close(vm_fd) == -1)
    {
        perror_extra(NULL);
    }

    error_after_mmap_guest_memory:
    munmap((void *) kvm_userspace_memory_region2.userspace_addr, guest_memory_size);

    error_after_open_sev:
    if (close(sev_fd) == -1)
    {
        perror_extra(NULL);
    }

    error_after_open_kvm:
    if (close(kvm_fd) == -1)
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