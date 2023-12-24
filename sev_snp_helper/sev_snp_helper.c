#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/file.h>  // fget
#include <asm/kvm_host.h>
#include <linux/kvm_host.h>  // struct kvm

#include "sev_snp_helper.h"


#define KVM_ADDRESS_SPACE_NUM 2  // should be two because arch/x86/include/asm/kvm_host.h defines is at two and include/linux/kvm_host.h defines it to 1 only if undefined


//#define pr_helper_err(fmt, ...) pr_err(pr_fmt("sev-snp-helper: " fmt ), ##__VA_ARGS__)
#define sev_snp_helper_pr_err pr_err

//#define pr_helper_info(fmt, ...) pr_info(pr_fmt("sev-snp-helper: " fmt ), ##__VA_ARGS__)
#define sev_snp_helper_pr_info pr_info

#define sev_snp_helper_pr_debug pr_debug // not printed when "sudo dmesg -w"

static inline
struct kvm_memory_slot *my_id_to_memslot(struct kvm_memslots *slots)
{
    int i;
	struct kvm_memory_slot *slot;
	int idx = slots->node_idx;

    for (i = 0; i < 1 << 16; i++)
    {
	hash_for_each_possible(slots->id_hash, slot, id_node[idx], i) {
        sev_snp_helper_pr_info("i= %d\n", i);
        sev_snp_helper_pr_info("slot: %px\n", slot);
        sev_snp_helper_pr_info("slot id: %d\n", slot->id);
	}
    }
	return NULL;
}

static long __sev_snp_helper_ioctl_get_phys_addr(struct sev_snp_helper_get_phys_addr *sev_snp_helper_get_phys_addr)
{
    //int i, j;
    struct file *file_kvm;
    struct kvm *kvm;
    struct kvm_memslots *kvm_memslots;
    struct kvm_memory_slot *kvm_memory_slot;
    int as_id, id; // as_id = address space id; id is the slot inside of the address space as_id
    int as_ids, ids;  // for iterating
    int num_non_empty_as_0;

    as_id = sev_snp_helper_get_phys_addr->slot >> 16;
    id = (u16)sev_snp_helper_get_phys_addr->slot;

    sev_snp_helper_pr_info("as_id: %d\n", as_id);
    sev_snp_helper_pr_info("id: %d\n", id);
    
    file_kvm = fget(sev_snp_helper_get_phys_addr->kvm_fd);
    if (!file_kvm)
    {
        return -EBADF;
    }

    kvm = file_kvm->private_data;
    sev_snp_helper_pr_info("kvm: %px", kvm);

    if (kvm->memslots[0] == NULL && kvm->memslots[0] == NULL)
    {
        sev_snp_helper_pr_info("kvm->memslots points to NULL for both active and inactive address space.\n");
    }
    else {
        sev_snp_helper_pr_info("kvm->memslots points to something for either active and/or inactive address space.\n");
        sev_snp_helper_pr_info("Aborting because I expected something else.\n");
        return -EIO;
    }

    num_non_empty_as_0 = 0;
    for (as_ids = 0; as_ids < KVM_ADDRESS_SPACE_NUM; as_ids++)
    {
        for (ids = 0; ids < 2; ids++)
        {
            if (kvm_memslots_empty(&kvm->__memslots[as_ids][ids]))
            {
                sev_snp_helper_pr_info("Address space %d, memslots %d is EMPTY!\n", as_ids, ids);

            }
            else
            {
                sev_snp_helper_pr_info("Address space %d, memslots %d NOT empty!\n", as_ids, ids);
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
        sev_snp_helper_pr_err("Expected exactly one non empty memslots for address space 0 but got %d\n", num_non_empty_as_0);
        return -EIO;
    }
    else
    {
        sev_snp_helper_pr_info("Got exactly one non empty memslots for address space 0. Nice.\n");
    }

    // kvm_memory_slot = id_to_memslot(kvm_memslots, id); // this crashes ...
    sev_snp_helper_pr_info("kvm_memory_slot: %px\n", kvm_memory_slot);


    //kvm_memslots = kvm->memslots[as_id];  // kvm->memslots: /* The current active memslot set for each address space */
    //sev_snp_helper_pr_info("kvm_memslots: %px\n", kvm_memslots);

    //kvm_memslots = kvm->memslots[0];  // kvm->memslots: /* The current active memslot set for each address space */
    //sev_snp_helper_pr_info("kvm_memslots: %px\n", kvm);


/*
    if (kvm_memslots_empty(kvm_memslots))
    {
        sev_snp_helper_pr_info("The memslots of address space %d are EMPTY.\n", as_id);
    }
    else
    {
        sev_snp_helper_pr_info("The memslots of address space %d NOT empty.\n", as_id);
    }
    */

/*
    if (!kvm->memslots)
    {
        sev_snp_helper_pr_info("kvm->memslots is NULL\n");
        return -EIO;
    }
    if (kvm->memslots[0])
    {
        sev_snp_helper_pr_info("kvm->memslots[0] is NOT NULL\n");
        return -EIO;
    }
    if (!kvm->memslots[1])
    {
        sev_snp_helper_pr_info("kvm->memslots[1] is NULL\n");
        return -EIO;
    }
    if (kvm_memslots_empty(kvm->memslots[1]))
    {
        sev_snp_helper_pr_info("kvm->memslots[1] is EMPTY\n");
        return -EIO;
    }

    sev_snp_helper_pr_info("kvm->memslots[0]: %px\n", kvm->memslots[0]);

    sev_snp_helper_pr_info("sev_snp_helper_get_phys_addr->slot: %d\n", sev_snp_helper_get_phys_addr->slot);
    for (i = 1; i < KVM_ADDRESS_SPACE_NUM; i++)
    {
		for (j = 1; j < 2; j++)
        {
            if (!kvm_memslots_empty(&kvm->__memslots[i][j]))
            {
                sev_snp_helper_pr_info("__memslots[%d][%d] is not empty.", i, j);
                kvm_memory_slot = id_to_memslot(&kvm->__memslots[i][j], sev_snp_helper_get_phys_addr->slot); // https://elixir.bootlin.com/linux/latest/source/include/linux/kvm_host.h#L1023
                if (kvm_memory_slot)
                {
                    sev_snp_helper_pr_info("__memslots[%d][%d] is OUT SLOT.", i, j);
                }
            }
            //sev_snp_helper_pr_info("__memslots[%d][%d] empty: %px\n", i, j, kvm_memslots_empty(&kvm->__memslots[i][j]));
        }
    }


    // sev_snp_helper_pr_info("KVM_ADDRESS_SPACE_NUM: %d\n", KVM_ADDRESS_SPACE_NUM); should be two because arch/x86/include/asm/kvm_host.h defines is at two and include/linux/kvm_host.h defines it only if undefined
    sev_snp_helper_pr_info("kvm->nr_memslot_pages: %lu\n", kvm->nr_memslot_pages);
    sev_snp_helper_pr_info("kvm->memslots: %px\n", kvm->memslots);
    sev_snp_helper_pr_info("kvm->memslots[0]: %px\n", kvm->memslots[0]);
    sev_snp_helper_pr_info("kvm->memslots[1]: %px\n", kvm->memslots[1]);
    sev_snp_helper_pr_info("kvm_memslots_empty(kvm->memslots[1]): %d\n", kvm_memslots_empty(kvm->memslots[1])); // static inline bool kvm_memslots_empty(struct kvm_memslots *slots)

    //my_id_to_memslot(kvm->memslots[1]);
    kvm_memory_slot = id_to_memslot(kvm->memslots[1], sev_snp_helper_get_phys_addr->slot); // https://elixir.bootlin.com/linux/latest/source/include/linux/kvm_host.h#L1023
    sev_snp_helper_pr_info("id_to_memslot: %px\n", kvm_memory_slot);
    sev_snp_helper_get_phys_addr->phys_addr = 0;

*/
    return 0;
}

static long sev_snp_helper_ioctl_get_phys_addr(struct file *filep, unsigned int cmd, unsigned long arg)
{
    int ret;
    struct sev_snp_helper_get_phys_addr sev_snp_helper_get_phys_addr;

    if (!copy_from_user(&sev_snp_helper_get_phys_addr, (const void *) arg, sizeof(struct sev_snp_helper_get_phys_addr)))
    {
        return -EFAULT;
    }

    ret = __sev_snp_helper_ioctl_get_phys_addr(&sev_snp_helper_get_phys_addr);
    if (!ret)
    {
        if (!copy_to_user((void *) arg, &sev_snp_helper_get_phys_addr, sizeof(struct sev_snp_helper_get_phys_addr)))
        {
            return -EFAULT;
        }
    }
    return ret;
}

static long unlocked_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
    switch (cmd)
    {
        case SEV_SNP_HELPER_GET_PHYS_ADDR:
            return sev_snp_helper_ioctl_get_phys_addr(filep, cmd, arg); 
    }
    return -ENOIOCTLCMD;  // results in ENOTTY (https://www.kernel.org/doc/html/latest/driver-api/ioctl.html#return-code)
}


// https://linux-kernel-labs.github.io/refs/heads/master/labs/device_drivers.html#struct-file-operations
static const struct file_operations fops = {
    .unlocked_ioctl = unlocked_ioctl
};

// https://www.kernel.org/doc/html/latest/driver-api/misc_devices.html
static struct miscdevice miscdevice = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = SEV_SNP_HELPER_NAME,
    .fops = &fops
};


int __init sev_snp_helper_init(void)
{
    int ret;
    ret = misc_register(&miscdevice);
    if (ret)
    {
        sev_snp_helper_pr_err("misc_register: %d", ret);
        return 1;
    }

    sev_snp_helper_pr_info("module loaded\n");
    return 0;
}

void __exit sev_snp_helper_exit(void)
{
    misc_deregister(&miscdevice);

    sev_snp_helper_pr_info("module unloaded\n");
}

module_init(sev_snp_helper_init);
module_exit(sev_snp_helper_exit);
MODULE_LICENSE("GPL");