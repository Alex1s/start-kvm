#include <linux/fs.h>
#include <linux/miscdevice.h>

#include "sev_snp_helper.h"

#define DEV_NAME "sev_snp_helper"

// https://www.kernel.org/doc/html/latest/driver-api/ioctl.html#command-number-definitions
#define SEV_SNP_HELPER_GET_PHYS_ADDR _IOR('\0', 0, struct sev_snp_helper_get_phys_addr)

//#define pr_helper_err(fmt, ...) pr_err(pr_fmt("sev-snp-helper: " fmt ), ##__VA_ARGS__)
#define sev_snp_helper_pr_err pr_err

//#define pr_helper_info(fmt, ...) pr_info(pr_fmt("sev-snp-helper: " fmt ), ##__VA_ARGS__)
#define sev_snp_helper_pr_info pr_info

static long unlocked_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
    switch (cmd)
    {
        case SEV_SNP_HELPER_GET_PHYS_ADDR:
            return 0;
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
    .name = DEV_NAME,
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

    sev_snp_helper_pr_info("sev-snp-helper module loaded\n");
    return 0;
}

void __exit sev_snp_helper_exit(void)
{
    misc_deregister(&miscdevice);

    sev_snp_helper_pr_info("sev-snp-helper module unloaded\n");
}

module_init(sev_snp_helper_init);
module_exit(sev_snp_helper_exit);
MODULE_LICENSE("GPL");