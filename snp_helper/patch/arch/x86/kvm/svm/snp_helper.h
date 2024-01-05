#pragma once

// https://www.kernel.org/doc/html/latest/driver-api/ioctl.html#command-number-definitions
#define SEV_SNP_HELPER_GET_PHYS_ADDR 0xFFFFA0

// https://www.kernel.org/doc/html/latest/driver-api/ioctl.html#structure-layout
struct snp_helper_get_phys_addr {
    __u32 slot;
    __u64 phys_addr;
};