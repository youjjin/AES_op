#include "AES.h"

unsigned int cpucycles(void) { return __rdtsc(); }

int main(void)
{
	int i, n;

	
	unsigned char iv[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	unsigned char plaintext[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	unsigned char ciphertext[16] = { 0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 };
	unsigned char key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	unsigned char outstate[16] = { 0, };


	//printf("\n[AES_ENC]\n");
	//printf("\n[ECB_KAT_File_io()]\n");
	//printf("\n[ECB]\n");
	//printf("\n[CBC]\n");
	//printf("\n[CTR]\n");

	//printf("\n\[Plaintext]\n");
	//for (n = 0; n < 16; n++)
	//{
	//	printf("%02x ", plaintext[n]);
	//}
	//printf("\n");

	//printf("\n\[Key]\n");
	//for (n = 0; n < 16; n++)
	//{
	//	printf("%02x ", key[n]);
	//}
	//printf("\n");

	/*printf("\n\[ctr]\n");
	for (n = 0; n < 16; n++)
	{
		printf("%02x ", iv[n]);
	}
	printf("\n");*/

	
	/*****************************************************************/

	//unsigned long long cycles=0, cycles1, cycles2;
	//unsigned int loop = 10000;

	////for loop에 들어가는 것까지 안새주려고 시간을 포루프 안에서 돌려줄것이다.
	//for (i = 0; i < loop; i++)
	//{
	//	cycles1 = cpucycles();
	//	AES_ENC(plaintext, outstate, key);
	//	cycles2 = cpucycles();
	//	cycles += (cycles2 - cycles1);
	//}

	//printf("\n[loop = %d]cycles : %10lld\n", loop, cycles / loop);
	//cycles = 0;

	/////***************************************************************/

	//printf("\n\[ciphertext]\n");
	//for (n = 0; n < 16; n++)
	//{
	//	printf("%02x ", outstate[n]);
	//}
	

	/**********************복호화*************************/
	//printf("\n[AES_DEC]\n");
	//printf("\n\[Ciphertext]\n");
	//for (n = 0; n < 16; n++)
	//{
	//	printf("%02x ", ciphertext[n]);
	//}

	//printf("\n\[Key]\n");
	//for (n = 0; n < 16; n++)
	//{
	//	printf("%02x ", key[n]);
	//}
	//printf("\n");

	//	unsigned long long cycles=0, cycles1, cycles2;
	//unsigned int loop = 10000;

	//for loop에 들어가는 것까지 안새주려고 시간을 포루프 안에서 돌려줄것이다.
	//for (i = 0; i < loop; i++)
	//{
	//	cycles1 = cpucycles();
	//	AES_DEC(ciphertext, outstate, key);
	//	cycles2 = cpucycles();
	//	cycles += (cycles2 - cycles1);
	//}

	//printf("\n[loop = %d]cycles : %10lld\n", loop, cycles / loop);
	//cycles = 0;

	//printf("\n\[Plaintext]\n");
	//for (n = 0; n < 16; n++)
	//{
	//	printf("%02x ", outstate[n]);
	//}
	//printf("\n");

	///********KAT*********/
	ECB_KAT_File_io();
	//CBC_KAT_File_io();
	//CTR_KAT_File_io();

	///********MMT*********/
	//ECB_MMT_File_io();
	//CBC_MMT_File_io();
	//CTR_MMT_File_io();

	///********MCT*********/
	//ECB_MCT_File_io();
	//CBC_MCT_File_io();
	//CTR_MCT_File_io();
}