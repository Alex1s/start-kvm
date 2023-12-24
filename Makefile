CC := gcc
CFLAGS := -Wall -Werror -Wextra -std=gnu17 -pedantic

run-sev-snp: kvm-sev-snp
	cd sev_snp_helper && make
	sudo ./$^

kvm-sev-snp: kvm-sev-snp.c
	make clean
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: run clean

clean:
	make -C sev_snp_helper clean
	rm sev_snp_helper/Module.symvers
	rm -f kvm-sev-snp