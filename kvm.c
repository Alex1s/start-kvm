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
#define SEV_DEV "/dev/sev"
#define GUEST_MEMORY_SIZE 4096

// this is real mode assembly ...
static uint8_t guest_code[] = {
    0xB8, 0xAA, 0xAA, // mov $0xAAAA, %ax
    0xF4, // hlt
};

#define perror_extra(message) do { if (message == NULL) fprintf(stderr, "%s:%d (%s): %s\n", __FILE__, __LINE__, __func__, strerror(errno)); else fprintf(stderr, "%s:%d (%s): %s\n", __FILE__, __LINE__, __func__, (const char *)message);} while (0)

/*
extern void guest_code(void);
__asm__(
    ".align " STRINGIFY(GUEST_MEMORY_SIZE) "\n\t"
    ".global guest_code\n\t"
    "guest_code:\n\t"
    ".byte 0xB8, 0xAA, 0xAA, 0xf4, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB\n\t"
//    "mov $0xAAAAAAAAAAAAAAAA, %rax\n\t"
//    "mov $0xBBBBBBBBBBBBBBBB, %rbx\n\t"
    "jmp guest_code\n\t"
    ".align " STRINGIFY(GUEST_MEMORY_SIZE) "\n\t"
);
*/

/*
static void dump_memory_hex(void *addr, int len)
{
    unsigned char *ptr = (unsigned char *)addr;
    
    for (int i = 0; i < len; i++) {
        printf("%02X ", ptr[i]);
        if ((i + 1) % 16 == 0) { // Print 16 bytes per line
            //printf("");
        }
    }
    printf("\n");
}
*/

/*
static void dump_segment(const char *name, struct kvm_segment *seg)
{
    printf("%s: base=0x%llx limit=0x%x selector=0x%x type=0x%x present=0x%x dpl=0x%x db=0x%x s=0x%x l=0x%x g=0x%x avl=0x%x unusable=0x%x\n",
           name, seg->base, seg->limit, seg->selector, seg->type, seg->present, seg->dpl, seg->db, seg->s, seg->l, seg->g, seg->avl, seg->unusable);
}
*/

/*
static void dump_kvm_sregs(struct kvm_sregs *sregs)
{
    dump_segment("CS", &sregs->cs);
    dump_segment("DS", &sregs->ds);
    dump_segment("ES", &sregs->es);
    dump_segment("FS", &sregs->fs);
    dump_segment("GS", &sregs->gs);
    dump_segment("SS", &sregs->ss);
    dump_segment("TR", &sregs->tr);
    dump_segment("LDT", &sregs->ldt);

    printf("GDT: base=0x%llx limit=0x%x\n", sregs->gdt.base, sregs->gdt.limit);
    printf("IDT: base=0x%llx limit=0x%x\n", sregs->idt.base, sregs->idt.limit);

    printf("CR0=0x%llx CR2=0x%llx CR3=0x%llx CR4=0x%llx CR8=0x%llx\n",
           sregs->cr0, sregs->cr2, sregs->cr3, sregs->cr4, sregs->cr8);

    printf("EFER=0x%llx APIC_BASE=0x%llx\n", sregs->efer, sregs->apic_base);

    // Dump interrupt bitmap (skipping for brevity)
}
*/

/*
static void dump_kvm_regs(struct kvm_regs regs)
{
    printf("RAX=%016llx RBX=%016llx RCX=%016llx RDX=%016llx\n", regs.rax, regs.rbx, regs.rcx, regs.rdx);
    printf("RSI=%016llx RDI=%016llx RBP=%016llx RSP=%016llx\n", regs.rsi, regs.rdi, regs.rbp, regs.rsp);
    printf("R8 =%016llx R9 =%016llx R10=%016llx R11=%016llx\n", regs.r8, regs.r9, regs.r10, regs.r11);
    printf("R12=%016llx R13=%016llx R14=%016llx R15=%016llx\n", regs.r12, regs.r13, regs.r14, regs.r15);
    printf("RIP=%016llx RFL=%08llx\n", regs.rip, regs.rflags);
}
*/

int main()
{
    int kvm_fd = 0, sev_fd = 0;
    int error = 0;
    int ret = 0;
    void *ret_ptr = NULL;
    void *guest_memory = NULL;
    size_t guest_memory_size = 0;
    int vm_fd = 0;
    int vcpu_mmap_size = 0;
    struct kvm_run *kvm_run = NULL;
    struct kvm_userspace_memory_region kvm_userspace_memory_region = {0};
    int vcpu_fd = 0;
    struct kvm_regs kvm_regs = {.rip = 0};
	struct kvm_sregs kvm_sregs = {0};

    kvm_fd = open(KVM_DEV, O_RDONLY | O_CLOEXEC);
    if (kvm_fd == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_null;
    }

    sev_fd = open(SEV_DEV, O_RDONLY | O_CLOEXEC);
    if (sev_fd == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_open_kvm;
    }

    guest_memory_size = GUEST_MEMORY_SIZE;
    ret_ptr = mmap(NULL, guest_memory_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (ret_ptr == MAP_FAILED)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_open_sev;
    }
    memcpy((void *__restrict) ret_ptr, (void *__restrict) guest_code, sizeof(guest_code));
    guest_memory = ret_ptr;

    ret = ioctl(kvm_fd, KVM_CREATE_VM, 0);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_guest_memory;
    }
    vm_fd = ret;
    kvm_userspace_memory_region.slot = 0;
    kvm_userspace_memory_region.flags = 0;
    kvm_userspace_memory_region.guest_phys_addr = 0x0;
    kvm_userspace_memory_region.memory_size = guest_memory_size;
    kvm_userspace_memory_region.userspace_addr = (uintptr_t) guest_memory;

    ret = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &kvm_userspace_memory_region);
    if (ret == -1)
    {
        perror_extra(NULL);
        error = 1;
        goto error_after_mmap_guest_memory;
    }

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
    munmap((void *) kvm_userspace_memory_region.userspace_addr, guest_memory_size);

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