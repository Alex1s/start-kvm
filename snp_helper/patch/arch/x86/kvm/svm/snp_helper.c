#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/file.h>  // fget
#include <asm/kvm_host.h>
#include <linux/kvm_host.h>  // struct kvm

#include "snp_helper.h"


//#define KVM_ADDRESS_SPACE_NUM 2  // should be two because arch/x86/include/asm/kvm_host.h defines is at two and include/linux/kvm_host.h defines it to 1 only if undefined


//#define pr_helper_err(fmt, ...) pr_err(pr_fmt("sev-snp-helper: " fmt ), ##__VA_ARGS__)
#define snp_helper_pr_err pr_err

//#define pr_helper_info(fmt, ...) pr_info(pr_fmt("sev-snp-helper: " fmt ), ##__VA_ARGS__)
#define snp_helper_pr_info pr_info

#define snp_helper_pr_debug pr_debug // not printed when "sudo dmesg -w"

static int __snp_helper_gfn_to_pfn(struct kvm *kvm, struct snp_helper_gfn_to_pfn *snp_helper_gfn_to_pfn)
{
    struct kvm_memslots *kvm_memslots;
    struct kvm_memslot_iter kvm_memslot_iter;
    bool pfn_found;

    kvm_pfn_t pfn;
    int max_order;

    int ret;

    kvm_memslots = __kvm_memslots(kvm, 0); // address space id should always be zero and never 1, right ???
    pfn_found = false;
    kvm_for_each_memslot_in_gfn_range(&kvm_memslot_iter, kvm_memslots, snp_helper_gfn_to_pfn->gfn, snp_helper_gfn_to_pfn->gfn + 1) {
        ret = kvm_gmem_get_pfn(kvm, kvm_memslot_iter.slot, snp_helper_gfn_to_pfn->gfn, &pfn, &max_order);
        if (ret)
        {
            snp_helper_pr_info("kvm_gmem_get_pfn failed: %d\n", ret);
            continue;
        }
        pfn_found = true;
        break; // assume slots are never overlapping ...
    }
    if (!pfn_found)
    {
        snp_helper_pr_err("gfn %llx not found in any memslot in address space 0.\n", snp_helper_gfn_to_pfn->gfn);
        return -EINVAL;  // invalid gfn
    }

    snp_helper_gfn_to_pfn->pfn = pfn;
    return 0;
}

static int snp_helper_gfn_to_pfn(struct kvm *kvm, struct kvm_sev_cmd *sev_cmd)
{
    int ret;
    struct snp_helper_gfn_to_pfn snp_helper_gfn_to_pfn;

    if (copy_from_user(&snp_helper_gfn_to_pfn, (const void __user *) sev_cmd->data, sizeof(struct snp_helper_gfn_to_pfn)))
    {
        return -EFAULT;
    }

    ret = __snp_helper_gfn_to_pfn(kvm, &snp_helper_gfn_to_pfn);

    if (copy_to_user((void __user *) sev_cmd->data, &snp_helper_gfn_to_pfn, sizeof(struct snp_helper_gfn_to_pfn)))
    {
        return -EFAULT;
    }

    return ret;
}