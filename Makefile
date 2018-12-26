
obj-m := hello_func_test.o

KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

pkgdatadir = $(includedir)/rohc
pkgincludedir = $(includedir)/rohc
pkglibdir = $(libdir)/rohc
pkglibexecdir = $(libexecdir)/rohc

oldincludedir = /usr/include

cppcheck:
	$(AM_V_GEN)cppcheck \
				--quiet \
				-I /usr/include/

all:

	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:

	rm *o