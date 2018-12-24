
obj-m := hello.o \
		hello_test.o \
		hello_func.o \
		hello_rohc_test.o

KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

all:

	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:

	rm *o