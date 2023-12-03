CC := gcc
CFLAGS := -Wall -Werror -Wextra -std=gnu17 -pedantic

all: kvm kvm-sev

kvm: kvm.c
	make clean
	$(CC) $(CFLAGS) -E -o $@.i $^
	$(CC) $(CFLAGS) -o $@ $^
	objdump -d $@ > $@.lss

run: kvm
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

.PHONY: all run clean

clean:
	rm -f *.lss
	rm -f *.i
	rm -f kvm kvm-sev