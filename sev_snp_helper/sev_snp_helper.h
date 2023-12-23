#pragma once

// https://www.kernel.org/doc/html/latest/driver-api/ioctl.html#structure-layout
struct sev_snp_helper_get_phys_addr {
    __u32 kvm_fd;
    __u64 phys_addr;
};