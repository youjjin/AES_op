#include "AES.h"

unsigned char Sbox[256] = {
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
0x54, 0xbb, 0x16 };
//
//void Rcon(unsigned char* outstate, int round) //1라운드부터
//{
//	int n = round - 1, i;
//	unsigned char result = 1, tmp = 1;
//
//	if (round <= 8)
//	{
//		tmp = tmp << n;
//		outstate[0] = tmp;
//		outstate[1] = 0x00;
//		outstate[2] = 0x00;
//		outstate[3] = 0x00;
//	}
//	else //8보다 큰 라운드에서는 xtime 연산이 필요하다.
//	{
//		result = tmp << 7;
//		for (i = 0; i < (round - 8); i++)
//			result = Xtime(result);
//		outstate[0] = result;
//		outstate[1] = 0x00;
//		outstate[2] = 0x00;
//		outstate[3] = 0x00;
//	}
//}


void KeyExpansion(unsigned char* key, unsigned char* keyschedule, int round)
{
	unsigned char rcon_table[10][4] = { {0x01, 0x00, 0x00, 0x00}, {0x02, 0x00, 0x00, 0x00}, {0x04, 0x00, 0x00, 0x00}, {0x08, 0x00, 0x00, 0x00}, {0x10, 0x00, 0x00, 0x00},
	{0x20, 0x00, 0x00, 0x00}, {0x40, 0x00, 0x00, 0x00}, {0x80, 0x00, 0x00, 0x00}, {0x1b, 0x00, 0x00, 0x00}, {0x36, 0x00, 0x00, 0x00} };
	int i = 1, ind1, ind2;

	keyschedule[0] = key[0]; keyschedule[1] = key[1]; keyschedule[2] = key[2]; keyschedule[3] = key[3];
	keyschedule[4] = key[4]; keyschedule[5] = key[5]; keyschedule[6] = key[6]; keyschedule[7] = key[7];
	keyschedule[8] = key[8]; keyschedule[9] = key[9]; keyschedule[10] = key[10]; keyschedule[11] = key[11];
	keyschedule[12] = key[12]; keyschedule[13] = key[13]; keyschedule[14] = key[14]; keyschedule[15] = key[15];

	//두번째 라운드부터는 연산을 하고 구현
	while (i <= round)
	{
		ind1 = Xtime(i - 1); ind1 = Xtime(ind1); ind1 = Xtime(ind1); ind1 = Xtime(ind1); //16 * (i-1)
		ind2 = Xtime(i); ind2 = Xtime(ind2); ind2 = Xtime(ind2); ind2 = Xtime(ind2); // 16 * i

		// 먼저 마지막 1byte에 있는 아이들 가져와서 함수에 넣어줘야함..
		/***************************************************/ //0
 		keyschedule[ind2] = Sbox[keyschedule[13 + ind1]] ^ rcon_table[i-1][0] ^ keyschedule[ind1];
		keyschedule[ind2 + 1] = Sbox[keyschedule[14 + ind1]] ^ rcon_table[i - 1][1] ^ keyschedule[ind1 + 1];
		keyschedule[ind2 + 2] = Sbox[keyschedule[15 + ind1]] ^ rcon_table[i - 1][2] ^ keyschedule[ind1 + 2];
		keyschedule[ind2 + 3] = Sbox[keyschedule[12 + ind1]] ^ rcon_table[i - 1][3] ^ keyschedule[ind1 + 3];
		/**************************************************/ //4
		keyschedule[4 + ind2] = keyschedule[ind2] ^ keyschedule[4 + ind1];
		keyschedule[5 + ind2] = keyschedule[ind2 + 1] ^ keyschedule[5 + ind1];
		keyschedule[6 + ind2] = keyschedule[ind2 + 2] ^ keyschedule[6 + ind1];
		keyschedule[7 + ind2 ] = keyschedule[ind2 + 3] ^ keyschedule[7 + ind1];
		/**************************************************/ //8
		keyschedule[8 + ind2] = keyschedule[4 + ind2] ^ keyschedule[8 + ind1];
		keyschedule[9 + ind2] = keyschedule[5 + ind2] ^ keyschedule[9 + ind1];
		keyschedule[10 + ind2] = keyschedule[6 + ind2] ^ keyschedule[10 + ind1];
		keyschedule[11 + ind2] = keyschedule[7 + ind2] ^ keyschedule[11 + ind1];
		/**************************************************/ //12
		keyschedule[12 + ind2] = keyschedule[8 + ind2] ^ keyschedule[12 + ind1];
		keyschedule[13 + ind2] = keyschedule[9 + ind2] ^ keyschedule[13 + ind1];
		keyschedule[14 + ind2] = keyschedule[10 + ind2] ^ keyschedule[14 + ind1];
		keyschedule[15 + ind2] = keyschedule[11 + ind2] ^ keyschedule[15 + ind1];
		/**************************************************/
		i++;
	}
}

void AddSubBytes(unsigned char* instate, unsigned char* outstate, unsigned char* rkey) //SubBytes, ShiftRows, AddRoundKey를 합친것 마지막라운드에 쓰기위한 함수 
{
	outstate[0] = Sbox[instate[0]] ^ rkey[0];
	outstate[1] = Sbox[instate[5]] ^ rkey[1];
	outstate[2] = Sbox[instate[10]] ^ rkey[2];
	outstate[3] = Sbox[instate[15]] ^ rkey[3];
	outstate[4] = Sbox[instate[4]] ^ rkey[4];
	outstate[5] = Sbox[instate[9]] ^ rkey[5];
	outstate[6] = Sbox[instate[14]] ^ rkey[6];
	outstate[7] = Sbox[instate[3]] ^ rkey[7];
	outstate[8] = Sbox[instate[8]] ^ rkey[8];
	outstate[9] = Sbox[instate[13]] ^ rkey[9];
	outstate[10] = Sbox[instate[2]] ^ rkey[10];
	outstate[11] = Sbox[instate[7]] ^ rkey[11];
	outstate[12] = Sbox[instate[12]] ^ rkey[12];
	outstate[13] = Sbox[instate[1]] ^ rkey[13];
	outstate[14] = Sbox[instate[6]] ^ rkey[14];
	outstate[15] = Sbox[instate[11]] ^ rkey[15];
}

void AES_func(unsigned char* instate, unsigned char* outstate, unsigned char* rkey) //Mixcolume, SubBytes, ShiftRows, AddRoundKey를 합친것
{
	unsigned char tm;
	unsigned char tmp;

	tmp = Sbox[instate[0]] ^ Sbox[instate[5]] ^ Sbox[instate[10]] ^ Sbox[instate[15]];	
	tm = Sbox[instate[0]] ^ Sbox[instate[5]];
	tm = Xtime(tm);
	outstate[0] = (Sbox[instate[0]] ^ tm ^ tmp) ^ rkey[0];
	tm = Sbox[instate[5]] ^ Sbox[instate[10]];
	tm = Xtime(tm);
	outstate[1] = (Sbox[instate[5]] ^ tm ^ tmp) ^ rkey[1];
	tm = Sbox[instate[10]] ^ Sbox[instate[15]];
	tm = Xtime(tm);
	outstate[2] = (Sbox[instate[10]] ^ tm ^ tmp) ^ rkey[2];
	tm = Sbox[instate[15]] ^ Sbox[instate[0]];
	tm = Xtime(tm);
	outstate[3] = (Sbox[instate[15]] ^ tm ^ tmp) ^ rkey[3];

	/***********************************/
	
	tmp = Sbox[instate[4]] ^ Sbox[instate[9]] ^ Sbox[instate[14]] ^ Sbox[instate[3]];	
	tm = Sbox[instate[4]] ^ Sbox[instate[9]];
	tm = Xtime(tm);
	outstate[4] = (Sbox[instate[4]] ^ tm ^ tmp) ^ rkey[4];	
	tm = Sbox[instate[9]] ^ Sbox[instate[14]];
	tm = Xtime(tm);
	outstate[5] = (Sbox[instate[9]] ^ tm ^ tmp) ^ rkey[5];	
	tm = Sbox[instate[14]] ^ Sbox[instate[3]];
	tm = Xtime(tm);
	outstate[6] = (Sbox[instate[14]] ^ tm ^ tmp) ^ rkey[6];	
	tm = Sbox[instate[3]] ^ Sbox[instate[4]];
	tm = Xtime(tm);
	outstate[7] = (Sbox[instate[3]] ^ tm ^ tmp) ^ rkey[7];

	/*******************************************/
	
	tmp = Sbox[instate[8]] ^ Sbox[instate[13]] ^ Sbox[instate[2]] ^ Sbox[instate[7]];	
	tm = Sbox[instate[8]] ^ Sbox[instate[13]];	
	tm = Xtime(tm);
	outstate[8] = (Sbox[instate[8]] ^ tm ^ tmp) ^ rkey[8];
	tm = Sbox[instate[13]] ^ Sbox[instate[2]];	
	tm = Xtime(tm);
	outstate[9] = (Sbox[instate[13]] ^ tm ^ tmp) ^ rkey[9];
	tm = Sbox[instate[2]] ^ Sbox[instate[7]];	
	tm = Xtime(tm);
	outstate[10] = (Sbox[instate[2]] ^ tm ^ tmp) ^ rkey[10];
	tm = Sbox[instate[7]] ^ Sbox[instate[8]];
	tm = Xtime(tm);
	outstate[11] = (Sbox[instate[7]] ^ tm ^ tmp) ^ rkey[11];

	/*******************************************/

	tmp = Sbox[instate[12]] ^ Sbox[instate[1]] ^ Sbox[instate[6]] ^ Sbox[instate[11]];
	tm = Sbox[instate[12]] ^ Sbox[instate[1]];
	tm = Xtime(tm);
	outstate[12] = (Sbox[instate[12]] ^ tm ^ tmp) ^ rkey[12];
	tm = Sbox[instate[1]] ^ Sbox[instate[6]];
	tm = Xtime(tm);
	outstate[13] = (Sbox[instate[1]] ^ tm ^ tmp) ^ rkey[13];
	tm = Sbox[instate[6]] ^ Sbox[instate[11]];
	tm = Xtime(tm);
	outstate[14] = (Sbox[instate[6]] ^ tm ^ tmp) ^ rkey[14];
	tm = Sbox[instate[11]] ^ Sbox[instate[12]];
	tm = Xtime(tm);
	outstate[15] = (Sbox[instate[11]] ^ tm ^ tmp) ^ rkey[15];
}

//unsigned char가 1byte니깐 우리는 4*4byte를 짜야하므로 unsigned char를 사용한다.
void AES_ENC(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key)
{
	unsigned char instate[16] = { 0, }; //16byte
	unsigned char outstate[16] = { 0, }; //16byte
	unsigned char keyschedule[176] = { 0, }; //176byte
	unsigned char rkey[16] = { 0, }; //16byte

	KeyExpansion(key, keyschedule, 10);

	outstate[0] = plaintext[0] ^ key[0]; outstate[1] = plaintext[1] ^ key[1]; outstate[2] = plaintext[2] ^ key[2]; outstate[3] = plaintext[3] ^ key[3];
	outstate[4] = plaintext[4] ^ key[4]; outstate[5] = plaintext[5] ^ key[5]; outstate[6] = plaintext[6] ^ key[6]; outstate[7] = plaintext[7] ^ key[7];
	outstate[8] = plaintext[8] ^ key[8]; outstate[9] = plaintext[9] ^ key[9]; outstate[10] = plaintext[10] ^ key[10]; outstate[11] = plaintext[11] ^ key[11];
	outstate[12] = plaintext[12] ^ key[12]; outstate[13] = plaintext[13] ^ key[13]; outstate[14] = plaintext[14] ^ key[14]; outstate[15] = plaintext[15] ^ key[15];

	rkey[0] = keyschedule[16];	rkey[1] = keyschedule[17];	rkey[2] = keyschedule[18];	rkey[3] = keyschedule[19];
	rkey[4] = keyschedule[20];	rkey[5] = keyschedule[21];	rkey[6] = keyschedule[22];	rkey[7] = keyschedule[23];
	rkey[8] = keyschedule[24];	rkey[9] = keyschedule[25];	rkey[10] = keyschedule[26];	rkey[11] = keyschedule[27];
	rkey[12] = keyschedule[28];	rkey[13] = keyschedule[29];	rkey[14] = keyschedule[30];	rkey[15] = keyschedule[31];
	AES_func(outstate, instate, rkey);

	rkey[0] = keyschedule[32];	rkey[1] = keyschedule[33];	rkey[2] = keyschedule[34];	rkey[3] = keyschedule[35];	
	rkey[4] = keyschedule[36];	rkey[5] = keyschedule[37];	rkey[6] = keyschedule[38];	rkey[7] = keyschedule[39];	
	rkey[8] = keyschedule[40];	rkey[9] = keyschedule[41];	rkey[10] = keyschedule[42];	rkey[11] = keyschedule[43];
	rkey[12] = keyschedule[44];	rkey[13] = keyschedule[45];	rkey[14] = keyschedule[46];	rkey[15] = keyschedule[47];
	AES_func(instate, outstate, rkey);

	rkey[0] = keyschedule[48];	rkey[1] = keyschedule[49];	rkey[2] = keyschedule[50];	rkey[3] = keyschedule[51];
	rkey[4] = keyschedule[52];	rkey[5] = keyschedule[53];	rkey[6] = keyschedule[54];	rkey[7] = keyschedule[55];
	rkey[8] = keyschedule[56];	rkey[9] = keyschedule[57];	rkey[10] = keyschedule[58];	rkey[11] = keyschedule[59];
	rkey[12] = keyschedule[60];	rkey[13] = keyschedule[61];	rkey[14] = keyschedule[62];	rkey[15] = keyschedule[63];
	AES_func(outstate, instate, rkey);

	rkey[0] = keyschedule[64]; rkey[1] = keyschedule[65]; rkey[2] = keyschedule[66]; rkey[3] = keyschedule[67];
	rkey[4] = keyschedule[68]; rkey[5] = keyschedule[69]; rkey[6] = keyschedule[70]; rkey[7] = keyschedule[71];
	rkey[8] = keyschedule[72]; rkey[9] = keyschedule[73]; rkey[10] = keyschedule[74]; rkey[11] = keyschedule[75];
	rkey[12] = keyschedule[76];	rkey[13] = keyschedule[77];	rkey[14] = keyschedule[78];	rkey[15] = keyschedule[79];
	AES_func(instate, outstate, rkey);

	rkey[0] = keyschedule[80];	rkey[1] = keyschedule[81];	rkey[2] = keyschedule[82];	rkey[3] = keyschedule[83];
	rkey[4] = keyschedule[84];	rkey[5] = keyschedule[85];	rkey[6] = keyschedule[86];	rkey[7] = keyschedule[87];
	rkey[8] = keyschedule[88];	rkey[9] = keyschedule[89];	rkey[10] = keyschedule[90];	rkey[11] = keyschedule[91];
	rkey[12] = keyschedule[92];	rkey[13] = keyschedule[93];	rkey[14] = keyschedule[94];	rkey[15] = keyschedule[95];
	AES_func(outstate, instate, rkey);

	rkey[0] = keyschedule[96];	rkey[1] = keyschedule[97];	rkey[2] = keyschedule[98];	rkey[3] = keyschedule[99];
	rkey[4] = keyschedule[100];	rkey[5] = keyschedule[101];	rkey[6] = keyschedule[102];	rkey[7] = keyschedule[103];
	rkey[8] = keyschedule[104];	rkey[9] = keyschedule[105];	rkey[10] = keyschedule[106]; rkey[11] = keyschedule[107];
	rkey[12] = keyschedule[108]; rkey[13] = keyschedule[109]; rkey[14] = keyschedule[110];	rkey[15] = keyschedule[111];
	AES_func(instate, outstate, rkey);

	rkey[0] = keyschedule[112];	rkey[1] = keyschedule[113];	rkey[2] = keyschedule[114];	rkey[3] = keyschedule[115];
	rkey[4] = keyschedule[116];	rkey[5] = keyschedule[117];	rkey[6] = keyschedule[118];	rkey[7] = keyschedule[119];
	rkey[8] = keyschedule[120];	rkey[9] = keyschedule[121];	rkey[10] = keyschedule[122]; rkey[11] = keyschedule[123];
	rkey[12] = keyschedule[124]; rkey[13] = keyschedule[125]; rkey[14] = keyschedule[126]; rkey[15] = keyschedule[127];
	AES_func(outstate, instate, rkey);

	rkey[0] = keyschedule[128];	rkey[1] = keyschedule[129];	rkey[2] = keyschedule[130];	rkey[3] = keyschedule[131];
	rkey[4] = keyschedule[132];	rkey[5] = keyschedule[133];	rkey[6] = keyschedule[134];	rkey[7] = keyschedule[135];
	rkey[8] = keyschedule[136];	rkey[9] = keyschedule[137];	rkey[10] = keyschedule[138]; rkey[11] = keyschedule[139];
	rkey[12] = keyschedule[140]; rkey[13] = keyschedule[141]; rkey[14] = keyschedule[142];	rkey[15] = keyschedule[143];
	AES_func(instate, outstate, rkey);

	rkey[0] = keyschedule[144];	rkey[1] = keyschedule[145];	rkey[2] = keyschedule[146];	rkey[3] = keyschedule[147];
	rkey[4] = keyschedule[148];	rkey[5] = keyschedule[149];	rkey[6] = keyschedule[150];	rkey[7] = keyschedule[151];
	rkey[8] = keyschedule[152];	rkey[9] = keyschedule[153];	rkey[10] = keyschedule[154]; rkey[11] = keyschedule[155];
	rkey[12] = keyschedule[156]; rkey[13] = keyschedule[157]; rkey[14] = keyschedule[158]; rkey[15] = keyschedule[159];
	AES_func(outstate, instate, rkey);

	rkey[0] = keyschedule[160];	rkey[1] = keyschedule[161];	rkey[2] = keyschedule[162];	rkey[3] = keyschedule[163];
	rkey[4] = keyschedule[164];	rkey[5] = keyschedule[165];	rkey[6] = keyschedule[166];	rkey[7] = keyschedule[167];
	rkey[8] = keyschedule[168];	rkey[9] = keyschedule[169];	rkey[10] = keyschedule[170]; rkey[11] = keyschedule[171];
	rkey[12] = keyschedule[172]; rkey[13] = keyschedule[173]; rkey[14] = keyschedule[174];	rkey[15] = keyschedule[175];
	AddSubBytes(instate, outstate, rkey);//AddRoundKey, ShiftRows, SubBytes를 한번에 수행하는 함수

	ciphertext[0] = outstate[0]; ciphertext[1] = outstate[1]; ciphertext[2] = outstate[2]; ciphertext[3] = outstate[3];
	ciphertext[4] = outstate[4]; ciphertext[5] = outstate[5]; ciphertext[6] = outstate[6]; ciphertext[7] = outstate[7];
	ciphertext[8] = outstate[8]; ciphertext[9] = outstate[9]; ciphertext[10] = outstate[10]; ciphertext[11] = outstate[11];
	ciphertext[12] = outstate[12]; ciphertext[13] = outstate[13]; ciphertext[14] = outstate[14]; ciphertext[15] = outstate[15];

}