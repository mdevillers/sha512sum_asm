## sha512sum_asm

Simple implementation of sha512sum tool in x86_64 assembly.

Usage: 

`sha512sum_asm <file to hash>`

Assembling and linking:

`nasm -felf64 sha512sum_asm.asm`
`ld -o ./sha512sum_asm sha512sum_asm.o`

