CC := gcc
# KERNEL_VERSION := 6.6.0-rc1
# CFLAGS := -I/usr/src/linux-headers-$(KERNEL_VERSION)-snp-host-5a170ce1a082/include/uapi -Wall -Werror -Wextra -std=gnu17 -pedantic
CFLAGS := -Wall -Werror -Wextra -std=gnu17 -pedantic

all: kvm kvm-sev

kvm: kvm.c
	make clean
	$(CC) $(CFLAGS) -E -o $@.i $^
	$(CC) $(CFLAGS) -o $@ $^
	objdump -d $@ > $@.lss

run: kvm
	sudo ./$^

kvm-protected: kvm-protected.c
	make clean
	$(CC) $(CFLAGS) -E -o $@.i $^
	$(CC) $(CFLAGS) -o $@ $^
	objdump -d $@ > $@.lss

run-protected: kvm-protected
	sudo ./$^

kvm-sev: kvm-sev.c
	make clean
	$(CC) $(CFLAGS) -E -o $@.i $^
	$(CC) $(CFLAGS) -o $@ $^
	objdump -d $@ > $@.lss

run-sev: kvm-sev
	sudo ./$^

kvm-sev-es: kvm-sev-es.c
	make clean
	$(CC) $(CFLAGS) -E -o $@.i $^
	$(CC) $(CFLAGS) -o $@ $^
	objdump -d $@ > $@.lss

run-sev-es: kvm-sev-es
	sudo ./$^

kvm-sev-snp: kvm-sev-snp.c
	make clean
	$(CC) $(CFLAGS) -E -o $@.i $^
	$(CC) $(CFLAGS) -o $@ $^
	objdump -d $@ > $@.lss

run-sev-snp: kvm-sev-snp
	sudo ./$^

.PHONY: all run clean

clean:
	rm -f *.lss
	rm -f *.i
	rm -f kvm kvm-sev kvm-sev-es kvm-sev-snp