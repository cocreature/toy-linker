main: main.o
	ld -o main main.o

%.o: %.c
	gcc -nostdlib -Wno-main -Wall -c -o $@ $< -fPIC
