all:
	gcc -g inject.c /opt/elfmaster/lib/libelfmaster.a -o inject 
	gcc -no-pie test.c -o test
	gcc -c -fpic evil.c
	gcc -shared -o libevil.so evil.o -ldl
clean:
	rm -f inject test
