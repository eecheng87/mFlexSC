PWD := $(shell pwd)
MODULE_NAME = mFlexSC
obj-m := $(MODULE_NAME).o

all:
	make -C /lib/modules/`uname -r`/build M=$(PWD) modules

insert:
	sudo insmod $(MODULE_NAME).ko
remove:
	sudo rmmod $(MODULE_NAME)
clean:
	make -C /lib/modules/`uname -r`/build M=$(PWD) clean