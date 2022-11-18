#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[])
{
	unsigned char *p1, *p2, *p3;
	unsigned char buf[4];

	/*============hello.exe hello2.exe shell.bin的文件指针===========*/
	FILE *hello_fp = fopen(argv[1], "rb");
	FILE *hello2_fp = fopen(argv[2], "wb+");
	FILE *shell_fp = fopen("shell.bin", "rb+");


	/*=================复制hello.exe到hello2.exe=====================*/	
	fseek(hello_fp, 0x00, SEEK_END);
	long int len_hello = ftell(hello_fp);//获取hello.exe文件的总长度
	fseek(hello_fp, 0x00, SEEK_SET);
	p1 = (unsigned char *)malloc(len_hello);
	fread(p1, 1, len_hello, hello_fp);
	fwrite(p1, 1, len_hello, hello2_fp);

	/*====读取hello2.exe的文件头加到shell.bin后面生成shelldat.bin====*/	
	fseek(hello2_fp, 0x08, SEEK_SET);//把hello2.exe文件的文件指针移到+8处用于获取头文件大小
	memset(buf, 0, sizeof(buf));
	fread(buf, 1, 2, hello2_fp);
	unsigned int *a = (unsigned int*)buf;
	unsigned int len_hello_head = (*a)*0x10;//求算头文件大小
	fseek(hello2_fp, 0x00, SEEK_SET);//把hello2.exe文件的文件指针移到开头
	fseek(shell_fp, 0x00, SEEK_END);//把shell.bin文件的文件指针移到末尾
	p2 = (unsigned char *)malloc(len_hello_head);
	fread(p2, 1, len_hello_head, hello2_fp);
	fwrite(p2, 1, len_hello_head, shell_fp);
	
	/*===========对hello2.exe除头文件之外的内容异或33h==============*/
	fseek(hello_fp, len_hello_head, SEEK_SET);//把hello.exe文件的文件指针移到除头文件之外的内容的开头
	fseek(hello2_fp, len_hello_head, SEEK_SET);//把hello2.exe文件的文件指针移到除头文件之外的内容的开头
	unsigned char part[1];
	memset(part, 0, sizeof(part));
	unsigned int len_hello2_content = len_hello-len_hello_head;//除头文件之外的内容的长度
	while(len_hello2_content--){
		fread(part, 1, 1, hello_fp);
		part[0] ^= 0x33;
		fwrite(part, 1, 1, hello2_fp);
	}

	/*==============把shelldat.bin加到hello2.exe的末尾==============*/
	fseek(hello2_fp, 0x00, SEEK_END);//把hello2.exe文件的文件指针移到末尾
	fseek(shell_fp, 0x00, SEEK_END);
	long int len_shell = ftell(shell_fp);//获取shell.bin的总长度
	fseek(shell_fp, 0x00, SEEK_SET);
	p3 = (unsigned char *)malloc(len_shell);
	fread(p3, 1, len_shell, shell_fp);
	fwrite(p3, 1, len_shell, hello2_fp);

	/*===========修改hello2.exe文件头+6的重定位项为0================*/
	fseek(hello2_fp, 0x06, SEEK_SET);//把hello2.exe文件的文件指针移到+6处用于获取头文件大小
	memset(buf, 0, sizeof(buf));
	fwrite(buf, 1, 2, hello2_fp);

	/*=========修改hello2.exe文件头+2 +4的文件长度信息==============*/
	fseek(hello_fp, 0x02, SEEK_SET);//把hello.exe文件的文件指针移到+2处用于获取最后那个扇区中的字节数
	memset(buf, 0, sizeof(buf));
	fread(buf, 1, 2, hello_fp);
	unsigned int *b = (unsigned int*)buf;
	unsigned int len_hello_last = *b;//求算未修改exe文件的最后那个扇区中的字节数
	fseek(hello_fp, 0x04, SEEK_SET);//把hello.exe文件的文件指针移到+4处用于获取hello2.exe文件的实际长度
	memset(buf, 0, sizeof(buf));
	fread(buf, 1, 2, hello_fp);
	unsigned int *c = (unsigned int*)buf;
	unsigned int len_hello_actual = *c;//求算未修改exe文件的实际长度
	unsigned int len_hello2_last = len_hello_last + len_shell;
	unsigned int len_hello2_actual = len_hello_actual;
	long int flag;//用来标记新的hello2的最后扇区的字节数是否大于200h
	/*===得到新的扇区数和字节数===*/
	while(1){
		flag = len_hello2_last - 0x200;
		if(flag < 0) break;
		else{
			len_hello2_last -= 0x200;
			len_hello2_actual++;
		}
	}
	/*=把得到的新的结果写入hello2.exe文件的+2、+4处=*/
	b = &len_hello2_last;
	unsigned char *buf1 = (unsigned char *)b;
	fseek(hello2_fp, 0x02, SEEK_SET);
	fwrite(buf1, 1, 2, hello2_fp);
	c = &len_hello2_actual;
	unsigned char *buf2 = (unsigned char *)c;
	fseek(hello2_fp, 0x04, SEEK_SET);
	fwrite(buf2, 1, 2, hello2_fp);

	/*=================修改hello2.exe的Δcs:ip=======================*/
	//默认先将delta_cs设为0
	memset(buf, 0, sizeof(buf));
	fseek(hello2_fp, 0x16, SEEK_SET);
	fwrite(buf, 1, 2, hello2_fp);

	//求算原exe长度
	unsigned int len_hello2_ip;
	if(!len_hello_last){
		len_hello2_ip = len_hello_actual * 0x200 - len_hello_head;//如果最后一个扇区字节数为0
	}
	else{
		len_hello2_ip = len_hello_last + (len_hello_actual - 1) * 0x200 - len_hello_head;//如果最后一个扇区字节数不为0
	}
	b = &len_hello2_ip;
	unsigned char *buf3 = (unsigned char *)b;
	fseek(hello2_fp, 0x14, SEEK_SET);
	fwrite(buf3, 1, 2, hello2_fp);//写入ip对应的位置

	memset(buf, 0, sizeof(buf));
	fseek(hello2_fp, 0x14, SEEK_SET);
	fread(buf, 1, 2, hello2_fp);
	unsigned int *d = (unsigned int*)buf;
	unsigned int len_hello2_actual_ip = *d;//求算载入的ip值
	unsigned int len_hello2_cs = len_hello2_ip - len_hello2_actual_ip;//若原exe长度过大导致ip放不下，则放入Δcs中
	len_hello2_cs = len_hello2_cs / 0x10;//换算
	c = &len_hello2_cs;
	unsigned char *buf4 = (unsigned char *)c;
	fseek(hello2_fp, 0x16, SEEK_SET);
	fwrite(buf4, 1, 2, hello2_fp);//写入Δcs对应的位置

	fclose(hello_fp);
	fclose(hello2_fp);
	fclose(shell_fp);
	return 0;
} 
