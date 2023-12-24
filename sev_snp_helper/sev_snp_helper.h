#pragma once


#define SEV_SNP_HELPER_NAME "sev_snp_helper"
#define SEV_SNP_HELPER_DEV "/dev/" SEV_SNP_HELPER_NAME

// https://www.kernel.org/doc/html/latest/driver-api/ioctl.html#command-number-definitions
#define SEV_SNP_HELPER_GET_PHYS_ADDR _IOR('\0', 0, struct sev_snp_helper_get_phys_addr)

// https://www.kernel.org/doc/html/latest/driver-api/ioctl.html#structure-layout
struct sev_snp_helper_get_phys_addr {
    __u32 kvm_fd;
    __u32 slot;
    __u64 phys_addr;
};