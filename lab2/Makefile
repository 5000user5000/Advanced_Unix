
obj-m += cryptomod.o
ccflags-y += -DEXPORT_SYMTAB

all: 
	make -C ../dist/modulebuild M=$(PWD) modules


clean:
	rm -f cryptomod
	make -C ../dist/modulebuild M=$(PWD) clean
