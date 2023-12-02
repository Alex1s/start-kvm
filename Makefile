CC := gcc
CFLAGS := -Wall -Werror -Wextra -std=gnu17 -pedantic

all: kvm kvm-sev

kvm: kvm.c
	$(CC) $(CFLAGS) -E -o $@.i $^
	$(CC) $(CFLAGS) -o $@ $^
	objdump -d $@ > $@.lss

run: kvm
	make clean
	sudo ./$^

kvm-sev: kvm-sev.c
	$(CC) $(CFLAGS) -E -o $@.i $^
	$(CC) $(CFLAGS) -o $@ $^
	objdump -d $@ > $@.lss

run-sev: kvm-sev
	make clean
	sudo ./$^

.PHONY: all run clean

clean:
	rm -f *.lss
	rm -f *.i
	rm -f kvm kvm-sev