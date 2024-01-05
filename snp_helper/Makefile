LINUX_HOST_PATH ?= /mnt/data/AMDSEV-DOCKER/AMDSEV/linux/host/

.PHONY: clean patch load

load: build/arch/x86/kvm/kvm-amd.ko
	sudo modprobe -r kvm_amd  # unload
	sudo modprobe build/arch/x86/kvm/kvm-amd.ko  # load

build/arch/x86/kvm/kvm-amd.ko: patch
	make -C /mnt/data/AMDSEV-DOCKER/AMDSEV/linux/host/ M=$(PWD)/build/arch/x86/kvm

patch: build
	rsync -av patch/ build/

build: clean
	mkdir build

	mkdir -p build/arch/x86
	cp -r $(LINUX_HOST_PATH)/arch/x86/kvm build/arch/x86/kvm

	mkdir -p build/virt
	cp -r $(LINUX_HOST_PATH)/virt/kvm build/virt/kvm

	find build -type f \( -name "*.cmd" -o -name "*.o" -o -name "*.ko" -o -name "*.d" -o -name "*.mod" -o -name "*.order" -o -name ".gitignore" -o -name "*.symvers" -o -name "Kconfig" \) -exec rm {} +


clean:
	rm -rf build
