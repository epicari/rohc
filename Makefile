
obj-m := hello_func_test.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

INC := -I/usr/include/rohc

all:

	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	$(MAKE) -I $(INC)

clean:

	rm *o