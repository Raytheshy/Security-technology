#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[])
{
	unsigned char *p1, *p2, *p3;
	unsigned char buf[4];

	/*============hello.exe hello2.exe shell.bin���ļ�ָ��===========*/
	FILE *hello_fp = fopen(argv[1], "rb");
	FILE *hello2_fp = fopen(argv[2], "wb+");
	FILE *shell_fp = fopen("shell.bin", "rb+");


	/*=================����hello.exe��hello2.exe=====================*/	
	fseek(hello_fp, 0x00, SEEK_END);
	long int len_hello = ftell(hello_fp);//��ȡhello.exe�ļ����ܳ���
	fseek(hello_fp, 0x00, SEEK_SET);
	p1 = (unsigned char *)malloc(len_hello);
	fread(p1, 1, len_hello, hello_fp);
	fwrite(p1, 1, len_hello, hello2_fp);

	/*====��ȡhello2.exe���ļ�ͷ�ӵ�shell.bin��������shelldat.bin====*/	
	fseek(hello2_fp, 0x08, SEEK_SET);//��hello2.exe�ļ����ļ�ָ���Ƶ�+8�����ڻ�ȡͷ�ļ���С
	memset(buf, 0, sizeof(buf));
	fread(buf, 1, 2, hello2_fp);
	unsigned int *a = (unsigned int*)buf;
	unsigned int len_hello_head = (*a)*0x10;//����ͷ�ļ���С
	fseek(hello2_fp, 0x00, SEEK_SET);//��hello2.exe�ļ����ļ�ָ���Ƶ���ͷ
	fseek(shell_fp, 0x00, SEEK_END);//��shell.bin�ļ����ļ�ָ���Ƶ�ĩβ
	p2 = (unsigned char *)malloc(len_hello_head);
	fread(p2, 1, len_hello_head, hello2_fp);
	fwrite(p2, 1, len_hello_head, shell_fp);
	
	/*===========��hello2.exe��ͷ�ļ�֮����������33h==============*/
	fseek(hello_fp, len_hello_head, SEEK_SET);//��hello.exe�ļ����ļ�ָ���Ƶ���ͷ�ļ�֮������ݵĿ�ͷ
	fseek(hello2_fp, len_hello_head, SEEK_SET);//��hello2.exe�ļ����ļ�ָ���Ƶ���ͷ�ļ�֮������ݵĿ�ͷ
	unsigned char part[1];
	memset(part, 0, sizeof(part));
	unsigned int len_hello2_content = len_hello-len_hello_head;//��ͷ�ļ�֮������ݵĳ���
	while(len_hello2_content--){
		fread(part, 1, 1, hello_fp);
		part[0] ^= 0x33;
		fwrite(part, 1, 1, hello2_fp);
	}

	/*==============��shelldat.bin�ӵ�hello2.exe��ĩβ==============*/
	fseek(hello2_fp, 0x00, SEEK_END);//��hello2.exe�ļ����ļ�ָ���Ƶ�ĩβ
	fseek(shell_fp, 0x00, SEEK_END);
	long int len_shell = ftell(shell_fp);//��ȡshell.bin���ܳ���
	fseek(shell_fp, 0x00, SEEK_SET);
	p3 = (unsigned char *)malloc(len_shell);
	fread(p3, 1, len_shell, shell_fp);
	fwrite(p3, 1, len_shell, hello2_fp);

	/*===========�޸�hello2.exe�ļ�ͷ+6���ض�λ��Ϊ0================*/
	fseek(hello2_fp, 0x06, SEEK_SET);//��hello2.exe�ļ����ļ�ָ���Ƶ�+6�����ڻ�ȡͷ�ļ���С
	memset(buf, 0, sizeof(buf));
	fwrite(buf, 1, 2, hello2_fp);

	/*=========�޸�hello2.exe�ļ�ͷ+2 +4���ļ�������Ϣ==============*/
	fseek(hello_fp, 0x02, SEEK_SET);//��hello.exe�ļ����ļ�ָ���Ƶ�+2�����ڻ�ȡ����Ǹ������е��ֽ���
	memset(buf, 0, sizeof(buf));
	fread(buf, 1, 2, hello_fp);
	unsigned int *b = (unsigned int*)buf;
	unsigned int len_hello_last = *b;//����δ�޸�exe�ļ�������Ǹ������е��ֽ���
	fseek(hello_fp, 0x04, SEEK_SET);//��hello.exe�ļ����ļ�ָ���Ƶ�+4�����ڻ�ȡhello2.exe�ļ���ʵ�ʳ���
	memset(buf, 0, sizeof(buf));
	fread(buf, 1, 2, hello_fp);
	unsigned int *c = (unsigned int*)buf;
	unsigned int len_hello_actual = *c;//����δ�޸�exe�ļ���ʵ�ʳ���
	unsigned int len_hello2_last = len_hello_last + len_shell;
	unsigned int len_hello2_actual = len_hello_actual;
	long int flag;//��������µ�hello2������������ֽ����Ƿ����200h
	/*===�õ��µ����������ֽ���===*/
	while(1){
		flag = len_hello2_last - 0x200;
		if(flag < 0) break;
		else{
			len_hello2_last -= 0x200;
			len_hello2_actual++;
		}
	}
	/*=�ѵõ����µĽ��д��hello2.exe�ļ���+2��+4��=*/
	b = &len_hello2_last;
	unsigned char *buf1 = (unsigned char *)b;
	fseek(hello2_fp, 0x02, SEEK_SET);
	fwrite(buf1, 1, 2, hello2_fp);
	c = &len_hello2_actual;
	unsigned char *buf2 = (unsigned char *)c;
	fseek(hello2_fp, 0x04, SEEK_SET);
	fwrite(buf2, 1, 2, hello2_fp);

	/*=================�޸�hello2.exe�Ħ�cs:ip=======================*/
	//Ĭ���Ƚ�delta_cs��Ϊ0
	memset(buf, 0, sizeof(buf));
	fseek(hello2_fp, 0x16, SEEK_SET);
	fwrite(buf, 1, 2, hello2_fp);

	//����ԭexe����
	unsigned int len_hello2_ip;
	if(!len_hello_last){
		len_hello2_ip = len_hello_actual * 0x200 - len_hello_head;//������һ�������ֽ���Ϊ0
	}
	else{
		len_hello2_ip = len_hello_last + (len_hello_actual - 1) * 0x200 - len_hello_head;//������һ�������ֽ�����Ϊ0
	}
	b = &len_hello2_ip;
	unsigned char *buf3 = (unsigned char *)b;
	fseek(hello2_fp, 0x14, SEEK_SET);
	fwrite(buf3, 1, 2, hello2_fp);//д��ip��Ӧ��λ��

	memset(buf, 0, sizeof(buf));
	fseek(hello2_fp, 0x14, SEEK_SET);
	fread(buf, 1, 2, hello2_fp);
	unsigned int *d = (unsigned int*)buf;
	unsigned int len_hello2_actual_ip = *d;//���������ipֵ
	unsigned int len_hello2_cs = len_hello2_ip - len_hello2_actual_ip;//��ԭexe���ȹ�����ip�Ų��£�����릤cs��
	len_hello2_cs = len_hello2_cs / 0x10;//����
	c = &len_hello2_cs;
	unsigned char *buf4 = (unsigned char *)c;
	fseek(hello2_fp, 0x16, SEEK_SET);
	fwrite(buf4, 1, 2, hello2_fp);//д�릤cs��Ӧ��λ��

	fclose(hello_fp);
	fclose(hello2_fp);
	fclose(shell_fp);
	return 0;
} 
