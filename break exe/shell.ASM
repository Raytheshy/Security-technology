code segment
assume cs:code, ds:code
shell:
   call next
next:
   pop bx; BX=next的运行时的实际偏移地址
   sub bx, offset next; bx=main在运行时的实际偏移地址
   mov si, 0
   mov di, si
   mov cx, bx
   push ds
   push es
   push cs
   pop ds
   push cs
   pop es
;解密
decode:
   lodsb
   xor al, 33h
   stosb
   loop decode
   pop es
   pop ds
;做重定位
;计算程序的首段地址
;程序刚开始运行时ds=es=psp段地址
;因此首段地址=ds或es+10h
   mov bp, ds; mov bp, es
   add bp, 10h; bp就是首段地址
;获得重定项数
   mov cx, cs:[bx+head+06h]
;如果重定项位为0，则跳过重定位的过程
   cmp cx,0
   jz sssp
;让cs:si指向重定位表
   mov si, cs:[bx+head+18h]
;循环定位
   push es; 保护es的原值
reloc_next:
   mov di, cs:[bx+head+si]; 重定位项的偏移
   mov dx, cs:[bx+head+si+2]; 重定位项的delta_段地址
   add dx, bp; dx是重定位项的段地址
   mov es, dx
   add es:[di], bp
   add si, 4
   dec cx
   jnz reloc_next
   pop es; 恢复es的原值
;设置ss:sp
sssp:
   mov dx, cs:[bx+head+0Eh]
   add dx, bp
   mov sp, cs:[bx+head+10h]
   mov ss, dx
;设置cs:ip
   mov dx, cs:[bx+head+16h]
   add dx, bp
   push dx
   push word ptr cs:[bx+head+14h]
   retf
head label word; head是一个变量名, 类型为word,
               ; 但它只有名字及地址,没有值,
               ; 编译后不占内存空间
;head+06 重定位项数; word
;head+0E delta_ss
;head+10 sp
;head+14 ip
;head+16 delta_cs
;head+18 重定位表
code ends
end shell