#pragma once

// https://www.kernel.org/doc/html/latest/driver-api/ioctl.html#command-number-definitions
#define SNP_HELPER_GFN_TO_PFN 0xFFFFA0

// https://www.kernel.org/doc/html/latest/driver-api/ioctl.html#structure-layout
struct snp_helper_gfn_to_pfn {
    __u64 gfn;
    __u64 pfn;
};