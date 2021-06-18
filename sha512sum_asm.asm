
;+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 section .data
;+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

BUFFER_SIZE: equ 8*1024

IV dq 0x6a09e667f3bcc908, 0xbb67ae8584caa73b
   dq 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1
   dq 0x510e527fade682d1, 0x9b05688c2b3e6c1f
   dq 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179

KCONST dq 0x428a2f98d728ae22, 0x7137449123ef65cd,
    dq 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    dq 0x3956c25bf348b538, 0x59f111f1b605d019,
    dq 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    dq 0xd807aa98a3030242, 0x12835b0145706fbe,
    dq 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    dq 0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
    dq 0x9bdc06a725c71235, 0xc19bf174cf692694,
    dq 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    dq 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    dq 0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
    dq 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    dq 0x983e5152ee66dfab, 0xa831c66d2db43210,
    dq 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    dq 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    dq 0x06ca6351e003826f, 0x142929670a0e6e70,
    dq 0x27b70a8546d22ffc, 0x2e1b21385c26c926,
    dq 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    dq 0x650a73548baf63de, 0x766a0abb3c77b2a8,
    dq 0x81c2c92e47edaee6, 0x92722c851482353b,
    dq 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    dq 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    dq 0xd192e819d6ef5218, 0xd69906245565a910,
    dq 0xf40e35855771202a, 0x106aa07032bbd1b8,
    dq 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    dq 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    dq 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    dq 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    dq 0x748f82ee5defb2fc, 0x78a5636f43172f60,
    dq 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    dq 0x90befffa23631e28, 0xa4506cebde82bde9,
    dq 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    dq 0xca273eceea26619c, 0xd186b8c721c0c207,
    dq 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    dq 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    dq 0x113f9804bef90dae, 0x1b710b35131c471b,
    dq 0x28db77f523047d84, 0x32caab7b40c72493,
    dq 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    dq 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    dq 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    
file_descriptor dd 0 
file_size dd 0
file_bytes_read dd 0
messages_needed dd 0
msg_size dd 0

buf_cur_offset  dq 0
buf_next_offset dq 0
buf_end_offset  dq 0

; for printing hash
char db 0, 0
newline db 10, 0
characters db '0123456789abcdef', 0

filename_len dd 0

usage db 'Usage: sha512sum_asm <file>', 10, 0
USAGE_LEN equ $-usage

read_error db 'File read error !', 10, 0
READ_ERROR_LEN equ $-read_error
open_error db 'File open error !', 10, 0
OPEN_ERROR_LEN equ $-open_error
seek_error db 'File seek error !', 10, 0
SEEK_ERROR_LEN equ $-seek_error
close_error db 'File close error !', 10, 0
CLOSE_ERROR_LEN equ $-close_error

;+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 section .bss align=64
;+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

filename:       resb 1024
message:        resb 128    ; 1 message = 1024 bits
words:          resb 640    ; 1 word = 64-bit - storage for 80 words 
hash_out:       resb 64
file_buf:       resb BUFFER_SIZE+1
hash_print:     resb 129

;+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 section .text
;+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

global _start

;---------------------------------------------------------------------------
_start:
;---------------------------------------------------------------------------

    call parse_args
    call calc_file_size
    call open_file

; calculate number of messages needed
    call compute_nb_msg

    call hash_file

;---------------------------------------------------------------------------
exit:
;---------------------------------------------------------------------------
    mov rax, 60 ; syscall exit
    xor rdi, rdi
    syscall

;============================================================================
;  FUNCTIONS
;============================================================================

;============================================================================
 compute_words:
;============================================================================
    ; words 0-15
    ; copy 1024 bits from message
    lea esi, [message]
    lea edi, [words]

    %rep 16
    ;lodsq
    ;bswap rax
    ;stosq
    movbe rax, qword [esi]
    mov qword [edi], rax
    add esi, 8
    add edi, 8
    %endrep

    ; words 16-79
    mov r13d, 64
    lea esi, [words]

compute_words_loop: 

    mov rax, qword [esi+112] ; w2  (word_idx-2)
    mov rbx, qword [esi]    ; w16 (word_idx-16)
    mov rcx, qword [esi+8]  ; w15 (word_idx-15)
    mov rdx, qword [esi+72] ; w7  (word_idx-7)

    mov r15, rdx
    add r15, rbx

    ; calculate word
    ; word = sigma_1(word_idx-2) + word(word_idx-7) 
    ;      + sigma_0(word_idx-15) + word(word_idx-16)

    ; sigma_1(word) = ror(word2,19) ^ ror(word2,61) ^ shr(word2,6) 
    mov r8, rax
    ror r8, 19
    ;rorx r8, r8, 19
    mov r10, rax
    ;rorx r10, r10, 61
    ;ror r10, 61
    rol r10, 3
    xor r8, r10
    mov r11, rax
    ;mov r9, 6
    ;shrx r11, r11, r9
    shr r11, 6
    xor r8, r11
    add r15, r8

    ; sigma_0(word) = ror(word15,1) ^ ror(word15,8) ^ shr(word15,7) 
    mov r9, rcx
    ror r9, 1
    ;rorx r9, r9, 1
    mov r10, rcx
    ror r10, 8
    ;rorx r10, r10, 8
    xor r9, r10
    mov r11, rcx
    shr r11, 7
    ;mov r8, 7
    ;shrx r11, r11, r8
    xor r9, r11
    add r15, r9

    ; calculate word
    ; word = sigma_1(word_idx-2) + word(word_idx-7) 
    ;      + sigma_0(word_idx-15) + word(word_idx-16)

    ; store word
    ;mov rax, r15
    ;stosq
    mov qword [edi], r15
    add edi, 8
    add esi, 8

    add r13d, -1
    jne compute_words_loop

compute_words_end:
    ret

;============================================================================
  compute_rounds:
;============================================================================

    xor r15d, r15d

    lea eax, [IV]
    lea ebx, [hash_out]

    or r14d, r14d
    cmove esi, eax
    cmova esi, ebx

compute_rounds_init_hash_out:
    mov rbx, qword [esi]    ; a
    mov rcx, qword [esi+8]  ; b
    mov rdx, qword [esi+16] ; c
    mov rdi, qword [esi+24] ; d
    mov r8,  qword [esi+32] ; e
    mov r9,  qword [esi+40] ; f
    mov r10, qword [esi+48] ; g
    mov r11, qword [esi+56] ; h

compute_rounds_loop:
    mov r12d, r15d
    shl r12d, 3
    ;mov esi, 3
    ;shlx r12d, r12d, esi
    mov rsi, qword [KCONST + r12d]
    add rsi, qword [words + r12d]
    add rsi, r11

    ; compute new round: a, b, c, d, e, f, g, h
    ; old		a, b, c, d, e, f, g, h
    ; new	  A, B, C, D, E, F, G, H
    ;          a  b  c     e  f  g
    ; B=a, C=b, D=c, F=e, G=f, H=g

compute_rounds_sigma0:
    ; sigma0(a) = ROTR(a,28) ^ ROTR(a,34) ^ ROTR(a,39)
    mov r12, rbx
    ror r12, 28
    ;rorx r12, r12, 28
    mov r13, rbx
    ror r13, 34
    ;rorx r13, r13, 34
    xor r13, r12
    mov r12, rbx
    ;ror r12, 39
    rol r12, 25
    ;rorx r12, r12, 39
    xor r13, r12
    mov rax, r13

compute_rounds_sigma1:
    ; sigma1(e) = ROTR(e,14) ^ ROTR(e,18) ^ ROTR(e,41)
    mov r12, r8
    ror r12, 14
    ;rorx r12, r12, 14
    mov r13, r8
    ;ror r13, 18
    rorx r13, r13, 18
    xor r13, r12
    mov r12, r8
    ;ror r12, 41
    rol r12, 23
    ;rorx r12, r12, 41
    xor r13, r12
    add rsi, r13

compute_rounds_ch:
    ; ch(e,f,g) = (e AND f) ^ (NOT e AND g)
    mov r12, r8
    and r12, r9
    andn r13, r8, r10 
    ;mov r13, r8
    ;not r13
    ;and r13, r10
    xor r12, r13
    add rsi, r12

compute_rounds_maj:
    ; maj(a,b,c) = (a AND b) ^ (b AND c) ^ (c AND a)
    mov r12, rbx
    and r12, rcx
    mov r13, rcx
    and r13, rdx
    xor r12, r13
    mov r13, rdx
    and r13, rbx
    xor r12, r13
    add rax, r12

    ; T1 = h + sigma1(e) + ch + word(t) + K(t)
    ; rsi = T1
    ; T2 = sigma0(a) + maj(a,b,c)
    ; rax = T2

compute_rounds_maj_var:
    ; h = g
    mov r11, r10
    ; g = f
    mov r10, r9
    ; f = e
    mov r9, r8
    ; e = d + T1
    mov r8, rdi
    add r8, rsi
    ; d = c
    mov rdi, rdx
    ; c = b
    mov rdx, rcx
    ; b = a
    mov rcx, rbx
    ; a = T1 + T2
    mov rbx, rsi
    add rbx, rax

    inc r15d
    cmp r15d, 79
    jbe compute_rounds_loop

compute_rounds_end:
    ret

;============================================================================
 compute_hash:
;============================================================================

    lea esi, [hash_out]
    lea eax, [IV]
    
    or r14d, r14d
    cmova r12d, esi
    cmovbe r12d, eax

    ; a = rbx
    mov rax, qword [r12d]
    add rax, rbx
    mov qword [esi], rax
    ; b = rcx
    mov rax, qword [r12d+8]
    add rax, rcx
    mov qword [esi+8], rax
    ; c = rdx
    mov rax, qword [r12d+16]
    add rax, rdx
    mov qword [esi+16], rax
    ; d = rdi
    mov rax, qword [r12d+24]
    add rax, rdi
    mov qword [esi+24], rax
    ; e = r8
    mov rax, qword [r12d+32]
    add rax, r8
    mov qword [esi+32], rax
    ; f = r9
    mov rax, qword [r12d+40]
    add rax, r9
    mov qword [esi+40], rax
    ; g = r10
    mov rax, qword [r12d+48]
    add rax, r10
    mov qword [esi+48], rax
    ; h = r11
    mov rax, qword [r12d+56]
    add rax, r11
    mov qword [esi+56], rax
    
compute_hash_end:
    ret

;============================================================================
 print_newline:
;============================================================================

    push rbp
    mov rbp, rsp

    mov rax, 1
    mov rdi, rax
    lea rsi, [newline]
    mov rdx, rax
    syscall

    mov rsp, rbp
    pop rbp
    ret

;============================================================================
 print_hash:
;============================================================================

    push rbp
    mov rbp, rsp

    lea esi, [hash_out] 
    mov ecx, 8
    
    lea edi, [hash_print]
    mov byte [edi + 128], 0
    
conv_nb64_loop:
    lodsq
    mov r8, rax
    call conv_nb64_to_hex
    loop conv_nb64_loop

print_hash_to_screen:
    mov rax, 1              ; syscall write
    mov rdi, rax            ; fd = 1
    lea rsi, [hash_print]
    mov rdx, 128            ; nb of characters to print
    syscall

    call print_newline

print_hash_end:
    mov rsp, rbp
    pop rbp
    ret

;============================================================================
 conv_nb64_to_hex:
;============================================================================

    push rbp
    mov rbp, rsp

    push r8
    push r9
    push r10
    push r11
    push r12
    push rax

    ; input r8
    mov r12d, 8
    push r8

conv_nb64_to_hex_loop:
    pop r8

    ; r9 = char to convert
    mov r9, r8
    rol r9, 8
    push r9
    and r9, 0xFF

    ; r10 = first char
    mov r10, r9
    shr r10, 4
    mov al, byte [characters + r10]
    mov byte [edi], al
    inc edi

    ; r9 = second char
    mov r11, r10
    shl r11, 4
    sub r9, r11
    mov al, byte [characters + r9]
    mov byte [edi], al
    inc edi

    sub r12d, 1
    jne conv_nb64_to_hex_loop

    pop r8

    pop rax
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8

print_hex_nb64_end:
    mov rsp, rbp
    pop rbp
    ret

;============================================================================
 compute_nb_msg:
;============================================================================
    mov eax, [file_size]

    ; converting to bits
    mov ebx, eax
    shl ebx, 3

    ; rdx = filesize_bits % 1024
    mov ecx, ebx
    mov eax, 10
    shr ecx, 10
    shl ecx, 10
    mov edx, ebx
    sub edx, ecx

    ; padding = 896 - (filesize_bits % 1024)
    mov r8d, 896
    sub r8d, edx
    
    ; total_bits = filesize_bits + padding + 1028
    mov r9d, r8d
    add r9d, ebx
    add r9d, 128
    
    shr r9d, 10
    or r8d, r8d
    jns compute_nb_msg_end 
    inc r9d

compute_nb_msg_end:
    mov [messages_needed], r9d

    ret

;============================================================================
 open_file:
;============================================================================

; open file in read-only mode
    mov edi, filename
    mov eax, 2 ; syscall open
    xor esi, esi ; flags
    xor edx, edx ; mode
    syscall
    or eax, eax
    js error_open_file
    mov [file_descriptor], eax

    ret

;============================================================================
 calc_file_size:
;============================================================================

    call open_file

; calculate size of file
    mov eax, 8 ; syscall lseek
    mov edi, [file_descriptor]
    xor esi, esi
    mov edx, 2 ; SEEK_END
    syscall
    or eax, eax
    js error_seek_file  ; closing file in case of error
    mov [file_size], eax

    call close_file
    ret

;============================================================================
 read_file:
;============================================================================

read_file_syscall:
    ; read file
    xor eax, eax ; syscall read
    mov edi, [file_descriptor]
    mov esi, file_buf
    mov edx, BUFFER_SIZE ; read max. 8192 bytes
    syscall
    ; eax = 0: end of file
    ; eax > 0: bytes read
    ; eax < 0: error
    or eax, eax
    js error_read_file  ; closing file and terminate in case of error
    mov [file_bytes_read], eax

read_file_end:
    ret

;============================================================================
 close_file:
;============================================================================

close_file_syscall:
    mov eax, 3 ; syscall close
    mov edi, [file_descriptor]
    syscall
    or eax, eax
    js error_close_file

close_file_end:
    ret

;============================================================================
 hash_file:
;============================================================================

hash_file_loop:
    call read_file
    call update_sha512
    cmp dword [file_bytes_read], BUFFER_SIZE
    jge hash_file_loop
    
    call close_file
    call calc_sha512digest

hash_file_end:
    ret

;============================================================================
calc_sha512digest:
;============================================================================

    cmp dword [msg_size], 0
    jl calc_sha512digest_2

    call process_last_message
    mov dword [msg_size], -1

calc_sha512digest_2:
    call print_hash

calc_sha512digest_end:
    ret

;============================================================================
 update_sha512:
;============================================================================

    ; skip if nothing to do
    cmp dword [msg_size], 0
    jl update_sha512_end
    ;jg update_sha512_begin

    ; [msg_size] = 0
    ;mov eax, [file_bytes_read]
    ;mov dword [msg_size], eax

update_sha512_begin:
    ; buf_cur_offset: start of buffer
    ; buf_end_offset: end of buffer + 1 byte
    lea eax, [file_buf]
    mov dword [buf_cur_offset], eax
    add eax, [file_bytes_read]
    mov dword [buf_end_offset], eax
    mov ebp, eax

update_sha512_init_loop:
    mov eax, 128
    sub eax, dword [msg_size]

    ; update buf_next_offset
    mov esi, dword [buf_cur_offset]
    add esi, eax
    mov dword [buf_next_offset], esi

    ; process last chunk if buf_cur_offset > buf_end_offset
    cmp esi, ebp ; [buf_cur_offset] > [buf_end_offset] ?
    jg update_sha512_last_chunk

update_sha512_loop:
    ; copy data from buffer to message
    mov esi, dword [buf_cur_offset]
    lea edi, [message]
    add edi, dword [msg_size]
    mov ecx, dword [buf_next_offset]
    mov ebp, ecx
    sub ecx, esi
    rep movsb

    call process_message

    ; [buf_cur_offset] = [buf_next_offset]
    mov dword [buf_cur_offset], ebp
    mov dword [msg_size], 0

    add ebp, 128
    add dword [buf_next_offset], 128

    mov eax, dword [buf_end_offset]
    cmp ebp, eax ; [buf_cur_offset] <= [buf_end_offset] ?
    jle update_sha512_loop
    
update_sha512_last_chunk:
    ; compute remaining bytes
    mov eax, [buf_end_offset]
    sub eax, [buf_cur_offset]

    ; skip copy data if msg_size = 0
    mov ebp, [msg_size]
    or ebp, ebp
    je update_sha512_update_msg_size

    ; copy data from buffer to message
    ;lea edi, [message+ebp]
    lea edi, [message]
    mov ecx, eax
    rep movsb

update_sha512_update_msg_size:
    ; update message size
    mov ebx, ebp
    add ebx, eax
    mov dword [msg_size], ebx

update_sha512_end:
    ret

;============================================================================
 process_last_message:
;============================================================================

process_last_message_bit_1:
    mov edx, [msg_size]
    
    mov esi, dword [buf_cur_offset]
    lea edi, [message]
    mov ecx, edx
    rep movsb

    ; setting bit to 1 in the next bytes (0x80)
    mov byte [edi], 0x80
    inc edi
    inc edx

process_last_message_init_remain_bytes:
    ; initialize the remaining bytes to 0
    xor al, al
    mov ecx, 128
    sub ecx, edx
    rep stosb

process_last_message_case_extra_msg:
    ; case with one extra message
    mov eax, edx
    add eax, 16
    cmp eax, 128
    jle process_last_message_2

    call process_message

process_last_message_init_message:    
    ; initialize beginning of message (15 words of 64-bit)
    mov edi, message
    xor rax, rax
    ;mov ecx, 15
    ;rep stosq
    mov ecx, 120
    rep stosb

process_last_message_2:
    ; filling the file size in bits
    call fill_message_filesize
    call process_message

process_last_message_end:
    ret

;============================================================================
 fill_message_filesize:
;============================================================================

    ; adding file size (in bits) at the end
    ; high 64-bit
    mov eax, [file_size]
    shl eax, 3 ; convert filesize in bits
    lea edi, [message + 120]
    mov dword [edi], 0
    add edi, 4

    ; reverse byte order
    movbe dword [edi], eax

fill_message_filesize_end:
    ret

;============================================================================
 process_message:
;============================================================================

    ; compute word blocks
    call compute_words

    ; compute rounds
    call compute_rounds
    
    ; compute hash
    call compute_hash
    
    ; increment message index
    inc r14d

process_message_end:
    ret

;============================================================================
 print_usage:
;============================================================================

    mov rdi, 1              ; fd
    mov rsi, usage          ; buffer
    mov rdx, USAGE_LEN      ; char count
    mov rax, rdi            ; syscall 1 (write)
    syscall

    ret

;============================================================================
 print_open_error:
;============================================================================

    mov rdi, 1               ; fd
    mov rsi, open_error      ; buffer
    mov rdx, OPEN_ERROR_LEN  ; char count
    mov rax, rdi             ; syscall 1 (write)
    syscall

    ret

;============================================================================
 print_close_error:
;============================================================================

    mov rdi, 1                ; fd
    mov rsi, close_error      ; buffer
    mov rdx, CLOSE_ERROR_LEN  ; char count
    mov rax, rdi              ; syscall 1 (write)
    syscall

    ret

;============================================================================
 print_read_error:
;============================================================================

    mov rdi, 1               ; fd
    mov rsi, read_error      ; buffer
    mov rdx, READ_ERROR_LEN  ; char count
    mov rax, rdi             ; syscall 1 (write)
    syscall

    ret

;============================================================================
 print_seek_error:
;============================================================================

    mov rdi, 1               ; fd
    mov rsi, seek_error      ; buffer
    mov rdx, SEEK_ERROR_LEN  ; char count
    mov rax, rdi             ; syscall 1 (write)
    syscall

    ret

;============================================================================
 parse_args:
;============================================================================
    push rbp
    mov rbp, rsp

    mov rax, [rbp+16]
    cmp rax, 2
    je args_ok  
    call print_usage
    jmp exit

args_ok:
    mov rax, [rbp+32]
    mov rsi, rax
    mov rdi, filename

filename_loop:
    lodsb
    or al, al
    je filename_loop_end
    stosb
    inc dword [filename_len]
    jmp filename_loop
filename_loop_end:
    mov byte [rdi], 0

    mov rsp, rbp
    pop rbp
    ret

;============================================================================
 error_open_file:
;============================================================================
    call print_open_error
    jmp exit

;============================================================================
 error_close_file:
;============================================================================
    call print_close_error
    jmp exit

;============================================================================
 error_read_file:
;============================================================================
    call print_read_error
    call close_file
    jmp exit

;============================================================================
 error_seek_file:
;============================================================================
    call print_seek_error
    call close_file
    jmp exit

