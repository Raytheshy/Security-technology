code segment
assume cs:code, ds:code
shell:
   call next
next:
   pop bx; BX=next������ʱ��ʵ��ƫ�Ƶ�ַ
   sub bx, offset next; bx=main������ʱ��ʵ��ƫ�Ƶ�ַ
   mov si, 0
   mov di, si
   mov cx, bx
   push ds
   push es
   push cs
   pop ds
   push cs
   pop es
;����
decode:
   lodsb
   xor al, 33h
   stosb
   loop decode
   pop es
   pop ds
;���ض�λ
;���������׶ε�ַ
;����տ�ʼ����ʱds=es=psp�ε�ַ
;����׶ε�ַ=ds��es+10h
   mov bp, ds; mov bp, es
   add bp, 10h; bp�����׶ε�ַ
;����ض�����
   mov cx, cs:[bx+head+06h]
;����ض���λΪ0���������ض�λ�Ĺ���
   cmp cx,0
   jz sssp
;��cs:siָ���ض�λ��
   mov si, cs:[bx+head+18h]
;ѭ����λ
   push es; ����es��ԭֵ
reloc_next:
   mov di, cs:[bx+head+si]; �ض�λ���ƫ��
   mov dx, cs:[bx+head+si+2]; �ض�λ���delta_�ε�ַ
   add dx, bp; dx���ض�λ��Ķε�ַ
   mov es, dx
   add es:[di], bp
   add si, 4
   dec cx
   jnz reloc_next
   pop es; �ָ�es��ԭֵ
;����ss:sp
sssp:
   mov dx, cs:[bx+head+0Eh]
   add dx, bp
   mov sp, cs:[bx+head+10h]
   mov ss, dx
;����cs:ip
   mov dx, cs:[bx+head+16h]
   add dx, bp
   push dx
   push word ptr cs:[bx+head+14h]
   retf
head label word; head��һ��������, ����Ϊword,
               ; ����ֻ�����ּ���ַ,û��ֵ,
               ; �����ռ�ڴ�ռ�
;head+06 �ض�λ����; word
;head+0E delta_ss
;head+10 sp
;head+14 ip
;head+16 delta_cs
;head+18 �ض�λ��
code ends
end shell