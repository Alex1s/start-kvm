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

#define STR_HELPER(x) #x
#define STRINGIFY(x) STR_HELPER(x)

#define KVM_DEV "/dev/kvm"
#define GUEST_MEMORY_SIZE 4096

// this is real mode assembly ...
// needs to be page aligned to be protected memory
static uint8_t guest_code[GUEST_MEMORY_SIZE] __attribute__((aligned(GUEST_MEMORY_SIZE))) = {
    0xB8, 0xAA, 0xAA, // mov $0xAAAA, %ax
    0xF4, // hlt
};


#define perror_extra(message) do { if (message == NULL) fprintf(stderr, "%s:%d (%s): %s\n", __FILE__, __LINE__, __func__, strerror(errno)); else fprintf(stderr, "%s:%d (%s): %s\n", __FILE__, __LINE__, __func__, (const char *)message);} while (0)

// src: /usr/src/linux-headers-6.6.0-rc1-snp-host-5a170ce1a082/include/uapi/linux/kvm.h:2379
#undef KVM_SET_MEMORY_ATTRIBUTES
#define KVM_SET_MEMORY_ATTRIBUTES              _IOW(KVMIO,  0xd3, struct kvm_memory_attributes)

#define KVM_X86_SW_PROTECTED_VM	1


int main()
{
    int kvm_fd = -1;
    int error = -1;
    int ret = -1;
    void *ret_ptr = NULL;
    size_t guest_memory_size = GUEST_MEMORY_SIZE;
    int vm_fd = -1;
    int vcpu_mmap_size = -1;
    struct kvm_run *kvm_run = NULL;
    struct kvm_create_guest_memfd kvm_create_guest_memfd = {0};
    struct kvm_userspace_memory_region2 kvm_userspace_memory_region2 = {0};
    int vcpu_fd = -1;
    struct kvm_regs kvm_regs = {.rip = 0};
	struct kvm_sregs kvm_sregs = {0};

    printf("Running kvm-protected.c\n");

    kvm_fd = open(KVM_DEV, O_RDONLY | O_CLOEXEC);
    if (kvm_fd == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_null;
    }

    ret = ioctl(kvm_fd, KVM_CREATE_VM, KVM_X86_SW_PROTECTED_VM);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_guest_memory;
    }
    vm_fd = ret;

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
        goto error_after_open_kvm;
    }

    kvm_create_guest_memfd.size = guest_memory_size;
    kvm_create_guest_memfd.flags = 0;
    ret = ioctl(vm_fd, KVM_CREATE_GUEST_MEMFD, &kvm_create_guest_memfd);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_open_kvm;
    }
    int guest_memfd = ret;

    kvm_userspace_memory_region2.guest_phys_addr = 0x0;
    kvm_userspace_memory_region2.memory_size = guest_memory_size;
    kvm_userspace_memory_region2.userspace_addr = (uintptr_t) guest_code;
    kvm_userspace_memory_region2.gmem_offset = 0;
    kvm_userspace_memory_region2.gmem_fd = guest_memfd;
    kvm_userspace_memory_region2.flags = 0; // KVM_MEM_GUEST_MEMFD does not exist yet in our kernel version
    kvm_userspace_memory_region2.slot = 0;
    ret = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION2, &kvm_userspace_memory_region2);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_guest_memory;
    }

    // to if kvm_userspace_memory_region2 actually worked, lets overwrite the code
    // if it really worked overwriting the code should disturb the VM, because
    // the actual VM code was copied to the unmapped memory region (guest_memfd)
    //guest_code[0] = 0;
    //guest_code[0] = 0;
    //guest_code[0] = 0;

    ret = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_guest_memory;
    }
    vcpu_fd = ret;

    ret = ioctl(vcpu_fd, KVM_SET_REGS, &kvm_regs);
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
        perror_extra("VM did not exit for reason KVM_EXIT_HLT");
        error = 1;
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

    printf("All OK.\n");

    error_after_kvm_run:
    munmap(kvm_run, vcpu_mmap_size);

    error_after_mmap_vcpu:
    if (close(vcpu_fd) == -1)
    {
        perror_extra(NULL);
    }

    error_after_kvm_create_vcpu:
    close(vm_fd);

    error_after_mmap_guest_memory:

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