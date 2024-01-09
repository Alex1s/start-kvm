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

// based on /mnt/data/AMDSEV-DOCKER/AMDSEV/linux/host/arch/x86/virt/svm/sev.c sev_dump_rmpentry
static void sev_dump_rmpentry_fancy(u64 dumped_pfn)
{
	struct rmpentry e;
	u64 pfn, pfn_end;
	int level, ret;
	u64 *e_data;

	ret = __snp_lookup_rmpentry(dumped_pfn, &e, &level);
	if (ret) {
		pr_info("Failed to read RMP entry for PFN 0x%llx, error %d\n",
			dumped_pfn, ret);
		return;
	}

	e_data = (u64 *)&e;
	if (e.assigned) {
		pr_info("RMP entry for PFN 0x%llx: [high=0x%016llx low=0x%016llx]\n",
			dumped_pfn, e_data[1], e_data[0]);
        pr_info("\tassigned: %d\n", e.assigned);
        pr_info("\tpagesize: %d\n", e.pagesize);
        pr_info("\timmutable: %d\n", e.immutable);
        pr_info("\trsvd1: %d\n", e.rsvd1);
        pr_info("\tgpa: %llx\n", (long long unsigned) e.gpa);
        pr_info("\tasid: %d\n", e.asid);
        pr_info("\tvmsa: %d\n", e.vmsa);
        pr_info("\tvalidated: %d\n", e.validated);
        pr_info("\trsvd2: %d\n", e.rsvd2);
        pr_info("\trsvd3: %llu\n", e.rsvd3);
		return;
	}

	/*
	 * If the RMP entry for a particular PFN is not in an assigned state,
	 * then it is sometimes useful to get an idea of whether or not any RMP
	 * entries for other PFNs within the same 2MB region are assigned, since
	 * those too can affect the ability to access a particular PFN in
	 * certain situations, such as when the PFN is being accessed via a 2MB
	 * mapping in the host page table.
	 */
	pfn = ALIGN(dumped_pfn, PTRS_PER_PMD);
	pfn_end = pfn + PTRS_PER_PMD;

	while (pfn < pfn_end) {
		ret = __snp_lookup_rmpentry(pfn, &e, &level);
		if (ret) {
			pr_info_ratelimited("Failed to read RMP entry for PFN 0x%llx\n", pfn);
			pfn++;
			continue;
		}

		if (e_data[0] || e_data[1]) {
			pr_info("No assigned RMP entry for PFN 0x%llx, but the 2MB region contains populated RMP entries, e.g.: PFN 0x%llx: [high=0x%016llx low=0x%016llx]\n",
				dumped_pfn, pfn, e_data[1], e_data[0]);
			return;
		}
		pfn++;
	}

	pr_info("No populated RMP entries in the 2MB region containing PFN 0x%llx\n",
		dumped_pfn);
}

static void change_rmp_entry(u64 pfn)
{
    void *page;
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
    sev_dump_rmpentry_fancy(virt_to_phys(page) >> PAGE_SHIFT);
    kfree(page);

    snp_helper_pr_info("Now the vm page:\n");
    sev_dump_rmpentry_fancy(pfn);
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