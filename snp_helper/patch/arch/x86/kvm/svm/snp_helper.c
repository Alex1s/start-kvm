#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/file.h>  // fget
#include <asm/kvm_host.h>
#include <linux/kvm_host.h>  // struct kvm

#include "snp_helper.h"


#define KVM_ADDRESS_SPACE_NUM 2  // should be two because arch/x86/include/asm/kvm_host.h defines is at two and include/linux/kvm_host.h defines it to 1 only if undefined


//#define pr_helper_err(fmt, ...) pr_err(pr_fmt("sev-snp-helper: " fmt ), ##__VA_ARGS__)
#define snp_helper_pr_err pr_err

//#define pr_helper_info(fmt, ...) pr_info(pr_fmt("sev-snp-helper: " fmt ), ##__VA_ARGS__)
#define snp_helper_pr_info pr_info

#define snp_helper_pr_debug pr_debug // not printed when "sudo dmesg -w"

static inline
struct kvm_memory_slot *my_id_to_memslot(struct kvm_memslots *slots)
{
    int i;
	struct kvm_memory_slot *slot;
	int idx = slots->node_idx;

    for (i = 0; i < 1 << 16; i++)
    {
	hash_for_each_possible(slots->id_hash, slot, id_node[idx], i) {
        snp_helper_pr_info("i= %d\n", i);
        snp_helper_pr_info("slot: %px\n", slot);
        snp_helper_pr_info("slot id: %d\n", slot->id);
	}
    }
	return NULL;
}

static int __snp_helper_get_phys_addr(struct kvm *kvm, struct snp_helper_get_phys_addr *snp_helper_get_phys_addr)
{
    struct kvm_memslots *kvm_memslots;
    struct kvm_memory_slot *kvm_memory_slot;
    int as_id, id; // as_id = address space id; id is the slot inside of the address space as_id
    int as_ids, ids;  // for iterating
    int num_non_empty_as_0;

    snp_helper_pr_info("KVM_MAX_NR_ADDRESS_SPACES: %d\n", KVM_MAX_NR_ADDRESS_SPACES);  // previously known as KVM_ADDRESS_SPACE_NUM
    snp_helper_pr_info("sizeof(struct kvm_memslots): %lx\n", sizeof(struct kvm_memslots));
    snp_helper_pr_info("4 * sizeof(struct kvm_memslots): %lx\n", 4 * sizeof(struct kvm_memslots));
    as_id = snp_helper_get_phys_addr->slot >> 16;
    id = (u16)snp_helper_get_phys_addr->slot;

    snp_helper_pr_info("as_id: %d\n", as_id);
    snp_helper_pr_info("id: %d\n", id);

    snp_helper_pr_info("kvm: %px", kvm);

    snp_helper_pr_info("kvm->mm: %px", kvm->mm);
    snp_helper_pr_info("current->mm: %px", current->mm);

    snp_helper_pr_info("kvm->memslots[0]: %px\n", kvm->memslots[0]);
    snp_helper_pr_info("kvm->memslots[1]: %px\n", kvm->memslots[1]);
    snp_helper_pr_info("__kvm_memslots(kvm, as_id): %px\n", __kvm_memslots(kvm, as_id));

    kvm_memslots = __kvm_memslots(kvm, as_id);
    
    snp_helper_pr_info("kvm_memslots->generation: %llu\n", kvm_memslots->generation);

    snp_helper_pr_info("id_to_memslot(kvm_memslots, id): %px\n",  id_to_memslot(kvm_memslots, id));

    if (kvm->memslots[0] == NULL && kvm->memslots[0] == NULL)
    {
        snp_helper_pr_info("kvm->memslots points to NULL for both active and inactive address space.\n");
    }
    else {
        snp_helper_pr_info("kvm->memslots points to something for either active and/or inactive address space.\n");
        snp_helper_pr_info("Aborting because I expected something else.\n");
        return -EIO;
    }

    num_non_empty_as_0 = 0;
    for (as_ids = 0; as_ids < KVM_ADDRESS_SPACE_NUM; as_ids++)
    {
        for (ids = 0; ids < 2; ids++)
        {
            if (kvm_memslots_empty(&kvm->__memslots[as_ids][ids]))
            {
                snp_helper_pr_info("Address space %d, memslots %d is EMPTY!\n", as_ids, ids);

            }
            else
            {
                snp_helper_pr_info("Address space %d, memslots %d NOT empty!\n", as_ids, ids);
                if (as_ids == 0)
                {
                    num_non_empty_as_0++;
                    kvm_memslots = &kvm->__memslots[as_ids][ids];
                }
            }
        }
    }

    if (num_non_empty_as_0 != 1)
    {
        snp_helper_pr_err("Expected exactly one non empty memslots for address space 0 but got %d\n", num_non_empty_as_0);
        return -EIO;
    }
    else
    {
        snp_helper_pr_info("Got exactly one non empty memslots for address space 0. Nice.\n");
    }

    // kvm_memory_slot = id_to_memslot(kvm_memslots, id); // this crashes ...
    snp_helper_pr_info("kvm_memory_slot: %px\n", kvm_memory_slot);


    //kvm_memslots = kvm->memslots[as_id];  // kvm->memslots: /* The current active memslot set for each address space */
    //snp_helper_pr_info("kvm_memslots: %px\n", kvm_memslots);

    //kvm_memslots = kvm->memslots[0];  // kvm->memslots: /* The current active memslot set for each address space */
    //snp_helper_pr_info("kvm_memslots: %px\n", kvm);


/*
    if (kvm_memslots_empty(kvm_memslots))
    {
        snp_helper_pr_info("The memslots of address space %d are EMPTY.\n", as_id);
    }
    else
    {
        snp_helper_pr_info("The memslots of address space %d NOT empty.\n", as_id);
    }
    */

/*
    if (!kvm->memslots)
    {
        snp_helper_pr_info("kvm->memslots is NULL\n");
        return -EIO;
    }
    if (kvm->memslots[0])
    {
        snp_helper_pr_info("kvm->memslots[0] is NOT NULL\n");
        return -EIO;
    }
    if (!kvm->memslots[1])
    {
        snp_helper_pr_info("kvm->memslots[1] is NULL\n");
        return -EIO;
    }
    if (kvm_memslots_empty(kvm->memslots[1]))
    {
        snp_helper_pr_info("kvm->memslots[1] is EMPTY\n");
        return -EIO;
    }

    snp_helper_pr_info("kvm->memslots[0]: %px\n", kvm->memslots[0]);

    snp_helper_pr_info("snp_helper_get_phys_addr->slot: %d\n", snp_helper_get_phys_addr->slot);
    for (i = 1; i < KVM_ADDRESS_SPACE_NUM; i++)
    {
		for (j = 1; j < 2; j++)
        {
            if (!kvm_memslots_empty(&kvm->__memslots[i][j]))
            {
                snp_helper_pr_info("__memslots[%d][%d] is not empty.", i, j);
                kvm_memory_slot = id_to_memslot(&kvm->__memslots[i][j], snp_helper_get_phys_addr->slot); // https://elixir.bootlin.com/linux/latest/source/include/linux/kvm_host.h#L1023
                if (kvm_memory_slot)
                {
                    snp_helper_pr_info("__memslots[%d][%d] is OUT SLOT.", i, j);
                }
            }
            //snp_helper_pr_info("__memslots[%d][%d] empty: %px\n", i, j, kvm_memslots_empty(&kvm->__memslots[i][j]));
        }
    }


    // snp_helper_pr_info("KVM_ADDRESS_SPACE_NUM: %d\n", KVM_ADDRESS_SPACE_NUM); should be two because arch/x86/include/asm/kvm_host.h defines is at two and include/linux/kvm_host.h defines it only if undefined
    snp_helper_pr_info("kvm->nr_memslot_pages: %lu\n", kvm->nr_memslot_pages);
    snp_helper_pr_info("kvm->memslots: %px\n", kvm->memslots);
    snp_helper_pr_info("kvm->memslots[0]: %px\n", kvm->memslots[0]);
    snp_helper_pr_info("kvm->memslots[1]: %px\n", kvm->memslots[1]);
    snp_helper_pr_info("kvm_memslots_empty(kvm->memslots[1]): %d\n", kvm_memslots_empty(kvm->memslots[1])); // static inline bool kvm_memslots_empty(struct kvm_memslots *slots)

    //my_id_to_memslot(kvm->memslots[1]);
    kvm_memory_slot = id_to_memslot(kvm->memslots[1], snp_helper_get_phys_addr->slot); // https://elixir.bootlin.com/linux/latest/source/include/linux/kvm_host.h#L1023
    snp_helper_pr_info("id_to_memslot: %px\n", kvm_memory_slot);
    snp_helper_get_phys_addr->phys_addr = 0;

*/
    return 0;
}

static int snp_helper_get_phys_addr(struct kvm *kvm, struct kvm_sev_cmd *sev_cmd)
{
    int ret;
    struct snp_helper_get_phys_addr snp_helper_get_phys_addr;

    if (!copy_from_user(&snp_helper_get_phys_addr, (const void __user *) sev_cmd->data, sizeof(struct snp_helper_get_phys_addr)))
    {
        return -EFAULT;
    }

    ret = __snp_helper_get_phys_addr(kvm, &snp_helper_get_phys_addr);

    if (!copy_to_user((void __user *) sev_cmd->data, &snp_helper_get_phys_addr, sizeof(struct snp_helper_get_phys_addr)))
    {
        return -EFAULT;
    }

    return ret;
}