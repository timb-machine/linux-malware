obj-m += jkit.o

MODULES = jkit.ko

all: clean $(MODULES)

$(MODULES):
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f *.o *.ko Module.markers Module.symvers w_plus_x*.mod.c modules.order
