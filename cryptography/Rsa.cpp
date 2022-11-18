#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")


#define N "FF807E694D915875B13F47ACDDA61CE11F62E034150F84660BF34026ABAF8C37" /* 128-bit */
#define E "010001"
#define D "45AEF3CB207EAD939BBDD87C8B0F0CFCC5A366A5AF2AC5FE1261D7547C625F51" /* 256-bit */
/* P=F910697533BDEFA1, Q=DDAE0595A4535E5D */

void dump_hex(unsigned char *p, int n, unsigned char *q)
{
   int i;
   for(i=0; i<n; i++)
   {
      sprintf((char *)&q[i*2], "%02X", p[i]);
   }
   q[i*2] = '\0';
}

void scan_hex(unsigned char *p, int n, unsigned char *q)
{
   int i;
   for(i=0; i<n; i++)
   {
      sscanf((char *)&p[i*2], "%02X", &q[i]);
   }
}

main()
{
   unsigned char plaintext[] = "01. A quick brown fox jumps over the lazy dog.\n" \
							               "02. A quick brown fox jumps over the lazy dog.\n" \
							               "03. A quick brown fox jumps over the lazy dog.\n";

   unsigned char ciphertext[512];
   unsigned char plaintextnew[512];
   unsigned char signature[288];
   unsigned char plaintext1[288];
   unsigned char plaintext2[288];
   unsigned char bufin[256];
   unsigned char bufout[256];
   unsigned char a[256];
   unsigned char b[256];
   int n,np,i,j,k,last;
   printf("plaintext=\n%s",plaintext);
   RSA *prsa;
   BIGNUM *pn, *pe, *pd;
   prsa = RSA_new();
   prsa->flags |= RSA_FLAG_NO_BLINDING; /* 在blinding模式下, 使用私钥加密或解密时都会
                                           使用公钥; 设置flags关闭blinding模式 */
   pn = BN_new();
   pe = BN_new();
   pd = BN_new();
   BN_hex2bn(&pn, N); /* N、E、D是调用RSA_generate_key()产生的 */
   BN_hex2bn(&pe, E);
   BN_hex2bn(&pd, D);

   /*==============公钥加密,私钥解密,NO_PADDING=============*/
   puts("Encrypting...");
   prsa->n = pn;
   prsa->e = pe;
   prsa->d = NULL;
   n = RSA_size(prsa); /* 返回N的字节数 */
   memset(bufin, 0, sizeof(bufin));
   np = sizeof(plaintext) / sizeof(char) - 1;/*明文的字节数*/
   unsigned char IV[] = "0123456789ABCDEFDEADBEEFBADBEAD!";
   memcpy(bufout,IV,n);
   for(i = 1;n*i <= np; i++){/*处理除去最后两块*/
	   memcpy(bufin, (plaintext + n*(i - 1)), n);
	   for (j = 0; j < n / 4; j++) {
		   ((unsigned int*)bufin)[j] = ((unsigned int*)bufin)[j] ^ ((unsigned int*)bufout)[j];/*CBC加密*/
	   }
	   n = RSA_public_encrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);/*rsa加密*/
	   if(n*(i + 1) <= np){
		   dump_hex(bufout, n, ciphertext + n*(i - 1)*2);
	   }
   }
   
   memcpy(a,bufout,n);/*处理最后两块*/
   last = np%n;/*最后一块字节数*/
   memset(bufin, 0, sizeof(bufin));
   memcpy(bufin, (plaintext + n*(i - 1)), last);
   for (j = 0; j < n / 4; j++) {
	   ((unsigned int*)bufin)[j] = ((unsigned int*)bufin)[j] ^ ((unsigned int*)bufout)[j];
   }
   n = RSA_public_encrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);/*rsa加密*/
   dump_hex(bufout, n, ciphertext + n*(i - 2)*2);
   dump_hex(a, last, ciphertext + n*(i - 1)*2);
   printf("ciphertext=\n%s\n", ciphertext);

   puts("Decrypting...");
   prsa->e = NULL;
   prsa->d = pd;
   memset(b,0,sizeof(b));
   for(i=1;n*(i + 1) <= np;i++){/*处理除去最后两块*/
	   scan_hex(ciphertext + n*(i - 1)*2, n, bufin);
	   n = RSA_private_decrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);/*rsa解密*/
	   if(i == 1) memcpy(b,IV,n);
	   for (j = 0; j < n / 4; j++) {
		   ((unsigned int*)bufout)[j] = ((unsigned int*)bufout)[j] ^ ((unsigned int*)b)[j];
	   }
	   memcpy((plaintextnew + n*(i - 1) ), bufout, n);
	   memcpy(b, bufin, n);
   }
   memcpy(a, b, n);/*处理最后两块*/
   scan_hex(ciphertext + n*(i - 1)*2, n, bufin);
   n = RSA_private_decrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);
   memset(b, 0, sizeof(b));
   scan_hex(ciphertext + n*i*2, last, b);
   for (j = 0; j < n / 4; j++) {
	   ((unsigned int*)bufout)[j] = ((unsigned int*)bufout)[j] ^ ((unsigned int*)b)[j];
   }
   memcpy((plaintextnew + n*i), bufout, last);
   memcpy(bufin,b,last);
   memcpy((bufin+last),(bufout+last),n-last);
   n = RSA_private_decrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);
   for (j = 0; j < n / 4; j++) {
	   ((unsigned int*)bufout)[j] = ((unsigned int*)bufout)[j] ^ ((unsigned int*)a)[j];
   }
   memcpy((plaintextnew + n*(i - 1)), bufout, n);
   ((unsigned char*)plaintextnew)[n*i+last] = '\0';/*去掉多余字符*/
   printf("plaintext=\n%s\n", plaintextnew);

 /*==============MD5=============*/
   puts("md5=");
   unsigned char md[17] = {0};
   MD5_CTX m;
   MD5_Init(&m);
   MD5_Update(&m, plaintext, (n*i + last));
   MD5_Final(md, &m);
   for(k=0; k<16; k++){
	   printf("%02X", md[k]);
   }
   printf("\n");

/*==============sha-1=============*/
   puts("sha-1=");
   unsigned char sha[21];
  // unsigned char string[300];
 //  strcpy((char *)string,(char *)plaintext);
   SHA_CTX s;
   SHA1_Init(&s);
   SHA1_Update(&s, plaintext, (n*i + last));
   SHA1_Final(sha, &s);
   for(k=0; k<20; k++){
	   printf("%02X", sha[k]);
   }
   printf("\n");

/*==============md5+sha-1=============*/
   puts("md5+sha-1=");
   unsigned char M[37];
   memcpy(M,md,16);
   memcpy(M+16,sha,20);
   for(k=0; k<36; k++){
	   printf("%02X", M[k]);
   }
   printf("\n");

 /*==============数字签名=============*/
   puts("Encrypting...");
   prsa->n = pn;
   prsa->e = NULL;
   prsa->d = pd;
   n = RSA_size(prsa); /* 返回N的字节数 */
   memcpy(bufin,M,n);
   n = RSA_private_encrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);
   memcpy(a,bufout,n);
   memcpy(bufin, M + n, 4);
   memcpy(bufin + 4, bufout + 4, n - 4);
   n = RSA_private_encrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);
   dump_hex(bufout, n, signature);
   dump_hex(a, 4, signature+n*2);
   printf("signature=\n%s\n", signature);

   
   puts("Decrypting...");
   prsa->e = pe;
   prsa->d = NULL;
   memset(plaintext1,0,sizeof(plaintext));
   scan_hex(signature, n, bufin);
   n = RSA_public_decrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);
   memcpy(b,bufout,n);
   scan_hex(signature+n*2, 4, bufin);
   memcpy(bufin + 4, bufout + 4, n - 4);
   n = RSA_public_decrypt(n, bufin, bufout, prsa, RSA_NO_PADDING);
   dump_hex(bufout, n, plaintext1);
   dump_hex(b, 4, plaintext1+n*2);
   printf("plaintext=\n%s\n", plaintext1);
   
   dump_hex(M,36,plaintext2);
   if(strcmp((char *)plaintext1, (char *)plaintext2) == 0) printf("Signature is correct.\n");/*验证签名*/

   RSA_free(prsa);
   getchar();
   return 0;
}