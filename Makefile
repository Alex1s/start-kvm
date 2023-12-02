CC := gcc
CFLAGS := -Wall -Werror -Wextra -std=gnu17 -pedantic

TARGET := kvm
SRC := kvm.c

all: $(TARGET)

$(TARGET): $(SRC)
	make clean
	$(CC) $(CFLAGS) -E -o $@.i $^
	$(CC) $(CFLAGS) -o $@ $^
	objdump -d $@ > $@.lss

run: $(TARGET)
	sudo ./$(TARGET)

.PHONY: all run clean

clean:
	rm -f $(TARGET) $(TARGET).lss $(TARGET).i