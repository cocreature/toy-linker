# Sections in main.o

1. `no name`: SHT_NULL: can be ignored (not shown in objdump)
2. `.text`: SHT_PROGBITS: code
3. `.data`: SHT_PROGBITS: data (size 0)
4. `.bss`: SHT_NOBITS: read-only data (size 0)
5. `.rodata.str1.1`: SHT_PROGBITS: probably the string
6. `.comment`: SHT_PROGBITS
7. `.note.GNU-stack`: SHT_PROGBITS
8. `.eh_frame`: SHT_PROGBITS
9. `.shstrtab`: SHT_STRTAB
