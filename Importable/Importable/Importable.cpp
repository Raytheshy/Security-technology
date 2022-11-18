#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//�����ڴ�ƫ��ת��Ϊ�ļ�ƫ��
unsigned int mem2file(FILE *pe_fp, unsigned int pe_head, unsigned int a);
//���ڴ�ӡdll����api��
void export(FILE *pe_fp,int mode);

int main(int argc, char *argv[])
{
	unsigned char buf[4];
	
	/*=========================�ļ�ָ��============================*/
	FILE *pe_fp = fopen(argv[1], "rb");

	/*=====================��ȡ�ļ���ͷ�ļ�========================*/	
	fseek(pe_fp, 0x3C, SEEK_SET);
	fread(buf, 1, 4, pe_fp);
	unsigned int *a = (unsigned int*)buf;
	unsigned int pe_head = *a;
	
	/*=============��ȡ�������ڴ�ƫ�Ʋ�ת��Ϊ�ļ�ƫ��============*/
	fseek(pe_fp, pe_head, SEEK_SET);//���ļ�ָ���Ƶ��ļ�ͷ��
	fseek(pe_fp, 0x80, SEEK_CUR);
	fread(buf, 1, 4, pe_fp);
	unsigned int *b = (unsigned int*)buf;
	unsigned int mem_offset = *b;
	unsigned int file_offset = mem2file(pe_fp, pe_head, mem_offset);//�ڴ�ƫ��ת��Ϊ�ļ�ƫ��

	/*====================����������ӡ����=======================*/
	while(1){
		/*=============��ȡ������е�dll����ת��Ϊ�ļ�ƫ��=============*/
		fseek(pe_fp, file_offset, SEEK_SET);//���ļ�ָ���Ƶ������ 
		fseek(pe_fp, 0x0C, SEEK_CUR);
		fread(buf, 1, 4, pe_fp);
		unsigned int *c = (unsigned int*)buf;
		unsigned int mem_dll = *c;//��ȡdll�����ڴ�ƫ�� 
		if(!mem_dll) break;
		unsigned int file_dll = mem2file(pe_fp, pe_head, mem_dll);//�ڴ�ƫ��ת��Ϊ�ļ�ƫ��

		/*======================��ȡ��dll�������======================*/
		fseek(pe_fp, file_dll, SEEK_SET);
		export(pe_fp, 1);//���dll�� 

		/*=========��ȡ������е�API����ָ���ת��Ϊ�ļ�ƫ��=========*/
		fseek(pe_fp, file_offset, SEEK_SET);//���ļ�ָ���Ƶ������
		fread(buf, 1, 4, pe_fp);
		unsigned int *d = (unsigned int*)buf;
		unsigned int mem_apitable = *d;//��ȡAPI����ָ�����ڴ�ƫ�� 
		unsigned int file_apitable = mem2file(pe_fp, pe_head, mem_apitable);//�ڴ�ƫ��ת��Ϊ�ļ�ƫ��

		/*====================����API����ָ����ӡ====================*/
		while(1){		
			fseek(pe_fp, file_apitable, SEEK_SET);//���ļ�ָ���Ƶ�API����ָ���
			fread(buf, 1, 4, pe_fp);
			unsigned int *e = (unsigned int*)buf;
			unsigned int mem_api = *e;
			if(!mem_api) break;
			if((mem_api & 0x80000000) != 0) printf("%d\n", mem_api & 0x7FFFFFFF);//�����API��ž�ֱ�������� 
			else{
				unsigned int file_api = mem2file(pe_fp, pe_head, mem_api);//�ڴ�ƫ��ת��Ϊ�ļ�ƫ��
				file_api += 0x02;
				fseek(pe_fp, file_api, SEEK_SET);
				export(pe_fp, 0);//���API�� 
			}
			file_apitable += 0x04;//����һ��API����ָ����в��� 
		}
		file_offset += 0x14;//����һ���������в��� 
	}
	fclose(pe_fp);
	return 0;
} 

unsigned int mem2file(FILE *pe_fp, unsigned int pe_head, unsigned int a)
{
	fseek(pe_fp, pe_head, SEEK_SET);//���ļ�ָ���Ƶ��ļ�ͷ��
	fseek(pe_fp, 0x104, SEEK_CUR);
	unsigned char buf[4];
	/*==============���㵱���ڴ�ƫ�ƴ����ĸ���===============*/ 
	while(1){		
		fread(buf, 1, 4, pe_fp);
		unsigned int *x = (unsigned int*)buf;
		unsigned int sec_mem_offset = *x;
		if(sec_mem_offset > a) break;
		fseek(pe_fp, 0x24, SEEK_CUR);
	}
	fseek(pe_fp, -0x2C, SEEK_CUR);
	fread(buf, 1, 4, pe_fp);
	unsigned int *x = (unsigned int*)buf;
	unsigned int sec_mem_offset = *x;//��ȡ����ڵ��ڴ�ƫ�� 
	unsigned int dif = a - sec_mem_offset;
	fseek(pe_fp, 0x04, SEEK_CUR);
	fread(buf, 1, 4, pe_fp);
	unsigned int *y = (unsigned int*)buf;
	unsigned int sec_file_offset = *y;//��ȡ����ڵ��ļ�ƫ��
	unsigned int result = sec_file_offset + dif;
	return result;
}

void export(FILE *pe_fp, int mode)
{
	char buffer[1];
	char res[50];
	memset(buffer, 0, sizeof(buffer));
	memset(res, 0, sizeof(res));
	int i = 0;
	while(1){
		fread(buffer, 1, 1, pe_fp);//���ֽڶ��� 
		res[i] = *buffer;
		if(!res[i]) break;//����������ȡ���� 
		i++;
	}
	if(mode) printf("%s:\n",res);//���dll�� 
	else printf("%s\n",res);//���API�� 
}