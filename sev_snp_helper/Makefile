obj-m += sev_snp_helper.o

.PHONY: clean load

load: sev_snp_helper.ko
	if lsmod | grep -q sev_snp_helper; then \
		sudo rmmod sev_snp_helper; \
	fi
	sudo insmod sev_snp_helper.ko

sev_snp_helper.ko: clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean