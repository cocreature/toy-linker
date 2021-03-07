main: main.o lib.o
	ld -o main main.o lib.o

%.o: %.c
	gcc -nostdlib -Wno-main -Wall -fPIC -fpie -c -o $@ $<

.PHONY : clean
clean:
	rm -rf *.o main
