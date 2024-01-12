#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/file.h>  // fget
#include <asm/kvm_host.h>
#include <linux/kvm_host.h>  // struct kvm

#include "snp_helper.h"
#include "local_symbols.h"

#define snp_helper_pr_err pr_err
#define snp_helper_pr_info pr_info
#define snp_helper_pr_debug snp_helper_pr_info

static void change_rmp_entry(u64 pfn)
{
    void *page;
    struct rmpentry rmpentry;
    int level;
    int ret;

    page = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!page)
    {
        snp_helper_pr_err("kmalloc\n");
        return;
    }
    if ((uintptr_t) page % PAGE_SIZE != 0)
    {
        snp_helper_pr_err("kmalloc not page aligned ...\n");
        kfree(page);
        return;
    }

    snp_helper_pr_info("A non VM page rmp entry for comparison:\n");  // they are ALL ZERO
    sev_dump_rmpentry(virt_to_phys(page) >> PAGE_SHIFT);
    kfree(page);

    snp_helper_pr_info("Now the vm page:\n");
    sev_dump_rmpentry(pfn);

    ret = __snp_lookup_rmpentry(pfn, &rmpentry, &level);
    if (ret)
    {
        snp_helper_pr_err("__snp_lookup_rmpentry: %d\n", ret);
        return;
    }
    if (level != PG_LEVEL_4K)
    {
        snp_helper_pr_err("vm page is not 4K, thus it has to bee 2M\n");
        return;
    }
    rmp_make_shared(pfn, level);

    snp_helper_pr_info("Now the vm page AFTER UPDATE:\n");
    sev_dump_rmpentry(pfn);
}

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

    change_rmp_entry(pfn);

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