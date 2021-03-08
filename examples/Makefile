main: main.o lib.o
	ld -o main main.o lib.o

dyn: dyn.o
	ld -o dyn dyn.o -lc

%.o: %.c
	gcc -nostdlib -Wno-main -Wall -c -o $@ $<

.PHONY : clean
clean:
	rm -rf *.o main
