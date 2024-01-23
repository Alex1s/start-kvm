LINUX_HOST_PATH ?= /mnt/data/AMDSEV-DOCKER/AMDSEV/linux/host/

.PHONY: clean patch unload load

load: unload build/arch/x86/kvm/kvm-amd.ko
	sudo modprobe rng_core; sudo modprobe irqbypass
	sudo modprobe ccp; sudo insmod ./build/arch/x86/kvm/kvm.ko

	sudo insmod ./build/arch/x86/kvm/kvm-amd.ko

unload:
	sudo modprobe -r kvm_amd
	sudo modprobe -r ccp; sudo modprobe -r kvm
	sudo modprobe -r rng_core; sudo modprobe -r irqbypass

build/arch/x86/kvm/kvm-amd.ko: patch/arch/x86/kvm/svm/local_symbols.h patch
	make -C /mnt/data/AMDSEV-DOCKER/AMDSEV/linux/host/ M=$(PWD)/build/arch/x86/kvm

patch/arch/x86/kvm/svm/local_symbols.h: patch/arch/x86/kvm/svm/local_symbols.h.template
	sed 's/sev_dump_rmpentry_ADDRESS/0x'$(shell sudo cat /proc/kallsyms|grep ' sev_dump_rmpentry'|awk '{print $$1}')'/g' $^ > $@

	sed -i 's/__snp_lookup_rmpentry_ADDRESS/0x'$(shell sudo cat /proc/kallsyms|grep ' __snp_lookup_rmpentry'|awk '{print $$1}')'/g' $@

patch: build
	rsync -av patch/ build/

build:
	mkdir build

	mkdir -p build/arch/x86
	cp -r $(LINUX_HOST_PATH)/arch/x86/kvm build/arch/x86/kvm

	mkdir -p build/virt
	cp -r $(LINUX_HOST_PATH)/virt/kvm build/virt/kvm

	find build -type f \( -name "*.cmd" -o -name "*.o" -o -name "*.ko" -o -name "*.d" -o -name "*.mod" -o -name "*.order" -o -name ".gitignore" -o -name "*.symvers" -o -name "Kconfig" \) -exec rm {} +


clean:
	rm -f patch/arch/x86/kvm/svm/local_symbols.h
	rm -rf build
