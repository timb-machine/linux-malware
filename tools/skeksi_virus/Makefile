all: virus
virus:
	gcc -O0 -DANTIDEBUG -DINFECT_PLTGOT  -fno-stack-protector -c virus.c -fpic -o virus.o
	#gcc -g -DDEBUG -O0 -fno-stack-protector -c virus.c -fpic -mcmodel=small -o virus.o
	gcc -N -fno-stack-protector -nostdlib virus.o -o virus
clean:
	rm -f virus
