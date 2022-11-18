#include<stdio.h>  
#include<string.h>  
#include<stdlib.h>

char rotor_table[5][27] =
{
	"EKMFLGDQVZNTOWYHXUSPAIBRCJ",
	"AJDKSIRUXBLHWTMCQGZNPYFVOE",
	"BDFHJLCPRTXVZNYEIWGAKMUSQO",
	"ESOVPZJAYQUIRHXLNFTGKDCMWB",
	"VZBRGITYUPSDNHLXAWMJQOFECK"
};

char reflector[27] = "YRUHQSLDPXNGOKMIEBFZCWVJAT";
char step_char[5] = "RFWKA"; // Royal Flags Wave Kings Above
char Plugboard[] = "POLMIUJKNHYTGBVFREDC";
char RingSetting[] = "TIP";
int RotorNum[3] = { 1,2,5 };

char* enigma_encrypt_decrypt(char *p, char *MessageKey);
//解密加密

char* enigma_encrypt_decrypt(char *p, char *MessageKey) {
	char plug[27] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char temp;
	int i, t;
	int buffer = 0;
	i = 0;
	while (Plugboard[i] != '\0') {
		int j = Plugboard[i] - 'A';
		int k = Plugboard[i + 1] - 'A';
		temp = plug[j];
		plug[j] = plug[k];
		plug[k] = temp;
		i = i + 2;
	}//制作plugboard表格
	
	i = 0;
	while (p[i] != '\0') {
		if (MessageKey[2] == 'A'&&MessageKey[1] == 'E') {
			MessageKey[1] = 'F';
			MessageKey[0] = (MessageKey[0] - 'A' + 1) % 26 + 'A';
		}
		MessageKey[2] = (MessageKey[2] - 'A' + 1) % 26 + 'A';
		if (MessageKey[2] == 'A') {
			MessageKey[1] = (MessageKey[1] - 'A' + 1) % 26 + 'A';
			if (MessageKey[1] == 'F') {
				MessageKey[0] = (MessageKey[0] - 'A' + 1) % 26 + 'A';
			}
		}                                                           //MessageKey变化
			
		buffer = p[i] - 'A';                                        //plugboard
		p[i] = plug[buffer];

		int delta = MessageKey[2] - RingSetting[2];                 //rotor5
		buffer = p[i] - 'A';
		p[i] = (buffer + delta + 26) % 26 + 'A';
		buffer = p[i] - 'A';
		p[i] = rotor_table[RotorNum[2] - 1][buffer];
		buffer = p[i] - 'A';
		p[i] = (buffer - delta + 26) % 26 + 'A';

		delta = MessageKey[1] - RingSetting[1];                     //rotor2
		buffer = p[i] - 'A';
		p[i] = (buffer + delta + 26) % 26 + 'A';
		buffer = p[i] - 'A';
		p[i] = rotor_table[RotorNum[1] - 1][buffer];
		buffer = p[i] - 'A';
		p[i] = (buffer - delta + 26) % 26 + 'A';

		delta = MessageKey[0] - RingSetting[0];                     //rotor1
		buffer = p[i] - 'A';
		p[i] = (buffer + delta + 26) % 26 + 'A';
		buffer = p[i] - 'A';
		p[i] = rotor_table[RotorNum[0] - 1][buffer];
		buffer = p[i] - 'A';
		p[i] = (buffer - delta + 26) % 26 + 'A';

		buffer = p[i] - 'A';                                        //reflector
		p[i] = reflector[buffer];

		delta = MessageKey[0] - RingSetting[0];                     //rotor1
		buffer = p[i] - 'A';
		p[i] = (buffer + delta + 26) % 26 + 'A';
		for (t = 0; rotor_table[RotorNum[0] - 1][t] != '\0'; t++) {
			if (p[i] == rotor_table[RotorNum[0] - 1][t])
				break;
		}
		p[i] = t + 'A';
		p[i] = (t - delta + 26) % 26 + 'A';

		delta = MessageKey[1] - RingSetting[1];                     //rotor2
		buffer = p[i] - 'A';
		p[i] = (buffer + delta + 26) % 26 + 'A';
		for (t = 0; rotor_table[RotorNum[1] - 1][t] != '\0'; t++) {
			if (p[i] == rotor_table[RotorNum[1] - 1][t])
				break;
		}
		p[i] = t + 'A';
		p[i] = (t - delta + 26) % 26 + 'A';

		delta = MessageKey[2] - RingSetting[2];                     //rotor5
		buffer = p[i] - 'A';
		p[i] = (buffer + delta + 26) % 26 + 'A';
		for (t = 0; rotor_table[RotorNum[2] - 1][t] != '\0'; t++) {
			if (p[i] == rotor_table[RotorNum[2] - 1][t])
				break;
		}
		p[i] = t + 'A';
		p[i] = (t - delta + 26) % 26 + 'A';

		buffer = p[i] - 'A';
		p[i] = plug[buffer];                    //plugboard*/
		i++;
	}
	return p;
}


int main() {
	char *px;
	char MK[4];
	int i, j, k, t;
	for (i = 0; i < 26; i++) {
		for (j = 0; j < 26; j++) {
			for (k = 0; k < 26; k++) {
				MK[0] = i + 'A';
				MK[1] = j + 'A';
				MK[2] = k + 'A';
				MK[3] = '\0';
				char p[500] = "CWNXPHVIOAIQOXMDZNOFWHUDUYWIWJNZWLCPSUDXDSEYNCLFFSJNWKDBFOBIKZPFGHWNYROEAUBPIJPFXXYVOTXOAJUFBTINEKSUOUNFZCDDPOJAFWJFKN";//密文赋值
				px = enigma_encrypt_decrypt(p, MK);    //进入加密解密算法
				t = 0;
				while (px[t + 5] != '\0') {
					if ((px[t] == 'T') && (px[t + 1] == 'U') && (px[t + 2] == 'R') && (px[t + 3] == 'I') && (px[t + 4] == 'N') && (px[t + 5] == 'G')) //判断是否含有TURING
					{
						MK[0] = i + 'A';
						MK[1] = j + 'A';
						MK[2] = k + 'A';
						MK[3] = '\0';
						//将MK还原成初始数值
						printf("MessageKey = ");
						puts(MK);
						printf("\n");
						printf("PlainText = ");
						puts(px);
						break;
					}
					t++;
				}
			}
		}
	}

	getchar();
}