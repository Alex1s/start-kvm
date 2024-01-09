#pragma once

// source: /mnt/data/AMDSEV-DOCKER/AMDSEV/linux/host/arch/x86/virt/svm/sev.c
/*
 * The RMP entry format is not architectural. The format is defined in PPR
 * Family 19h Model 01h, Rev B1 processor.
 */
struct rmpentry {
	u64	assigned	: 1,
		pagesize	: 1,
		immutable	: 1,
		rsvd1		: 9,
		gpa		: 39,
		asid		: 10,
		vmsa		: 1,
		validated	: 1,
		rsvd2		: 1;
	u64 rsvd3;
} __packed;

void (*sev_dump_rmpentry)(u64) = (void (*)(u64)) 0xffffffff810a1860;
int (*__snp_lookup_rmpentry)(u64, struct rmpentry *, int *) = (int (*)(u64, struct rmpentry *, int *)) 0xffffffff810a1760;