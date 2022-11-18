#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//用于内存偏移转换为文件偏移
unsigned int mem2file(FILE *pe_fp, unsigned int pe_head, unsigned int a);
//用于打印dll名和api名
void export(FILE *pe_fp,int mode);

int main(int argc, char *argv[])
{
	unsigned char buf[4];
	
	/*=========================文件指针============================*/
	FILE *pe_fp = fopen(argv[1], "rb");

	/*=====================获取文件的头文件========================*/	
	fseek(pe_fp, 0x3C, SEEK_SET);
	fread(buf, 1, 4, pe_fp);
	unsigned int *a = (unsigned int*)buf;
	unsigned int pe_head = *a;
	
	/*=============获取输入表的内存偏移并转换为文件偏移============*/
	fseek(pe_fp, pe_head, SEEK_SET);//把文件指针移到文件头处
	fseek(pe_fp, 0x80, SEEK_CUR);
	fread(buf, 1, 4, pe_fp);
	unsigned int *b = (unsigned int*)buf;
	unsigned int mem_offset = *b;
	unsigned int file_offset = mem2file(pe_fp, pe_head, mem_offset);//内存偏移转换为文件偏移

	/*====================根据输出表打印内容=======================*/
	while(1){
		/*=============获取输入表中的dll名并转换为文件偏移=============*/
		fseek(pe_fp, file_offset, SEEK_SET);//把文件指针移到输入表处 
		fseek(pe_fp, 0x0C, SEEK_CUR);
		fread(buf, 1, 4, pe_fp);
		unsigned int *c = (unsigned int*)buf;
		unsigned int mem_dll = *c;//获取dll名的内存偏移 
		if(!mem_dll) break;
		unsigned int file_dll = mem2file(pe_fp, pe_head, mem_dll);//内存偏移转换为文件偏移

		/*======================获取的dll名并输出======================*/
		fseek(pe_fp, file_dll, SEEK_SET);
		export(pe_fp, 1);//输出dll名 

		/*=========获取输入表中的API名字指针表并转换为文件偏移=========*/
		fseek(pe_fp, file_offset, SEEK_SET);//把文件指针移到输入表处
		fread(buf, 1, 4, pe_fp);
		unsigned int *d = (unsigned int*)buf;
		unsigned int mem_apitable = *d;//获取API名字指针表的内存偏移 
		unsigned int file_apitable = mem2file(pe_fp, pe_head, mem_apitable);//内存偏移转换为文件偏移

		/*====================根据API名字指针表打印====================*/
		while(1){		
			fseek(pe_fp, file_apitable, SEEK_SET);//把文件指针移到API名字指针表处
			fread(buf, 1, 4, pe_fp);
			unsigned int *e = (unsigned int*)buf;
			unsigned int mem_api = *e;
			if(!mem_api) break;
			if((mem_api & 0x80000000) != 0) printf("%d\n", mem_api & 0x7FFFFFFF);//如果是API序号就直接输出序号 
			else{
				unsigned int file_api = mem2file(pe_fp, pe_head, mem_api);//内存偏移转换为文件偏移
				file_api += 0x02;
				fseek(pe_fp, file_api, SEEK_SET);
				export(pe_fp, 0);//输出API名 
			}
			file_apitable += 0x04;//对下一个API名字指针进行操作 
		}
		file_offset += 0x14;//对下一个输入表进行操作 
	}
	fclose(pe_fp);
	return 0;
} 

unsigned int mem2file(FILE *pe_fp, unsigned int pe_head, unsigned int a)
{
	fseek(pe_fp, pe_head, SEEK_SET);//把文件指针移到文件头处
	fseek(pe_fp, 0x104, SEEK_CUR);
	unsigned char buf[4];
	/*==============计算当下内存偏移处于哪个节===============*/ 
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
	unsigned int sec_mem_offset = *x;//获取这个节的内存偏移 
	unsigned int dif = a - sec_mem_offset;
	fseek(pe_fp, 0x04, SEEK_CUR);
	fread(buf, 1, 4, pe_fp);
	unsigned int *y = (unsigned int*)buf;
	unsigned int sec_file_offset = *y;//获取这个节的文件偏移
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
		fread(buffer, 1, 1, pe_fp);//逐字节读入 
		res[i] = *buffer;
		if(!res[i]) break;//如果是零则读取结束 
		i++;
	}
	if(mode) printf("%s:\n",res);//输出dll名 
	else printf("%s\n",res);//输出API名 
}