#include "AES.h"


unsigned char ISbox[256] = {
0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54,
0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
0x21, 0x0c, 0x7d };

//void InvSubBytes(unsigned char* instate, unsigned char* outstate)
//{
//	outstate[0] = ISbox[instate[0]];
//	outstate[1] = ISbox[instate[13]];
//	outstate[2] = ISbox[instate[10]];
//	outstate[3] = ISbox[instate[7]];
//
//	outstate[4] = ISbox[instate[4]];
//	outstate[5] = ISbox[instate[1]];
//	outstate[6] = ISbox[instate[14]];
//	outstate[7] = ISbox[instate[11]];
//
//	outstate[8] = ISbox[instate[8]];
//	outstate[9] = ISbox[instate[5]];
//	outstate[10] = ISbox[instate[2]];
//	outstate[11] = ISbox[instate[15]];
//
//	outstate[12] = ISbox[instate[12]];
//	outstate[13] = ISbox[instate[9]];
//	outstate[14] = ISbox[instate[6]];
//	outstate[15] = ISbox[instate[3]];
//}

void AES_DEC_fun(unsigned char* instate, unsigned char* outstate, unsigned char* rkey)
{
	unsigned char tmp, step1, step2, step3; 

	tmp = ISbox[instate[0]] ^ ISbox[instate[13]] ^ ISbox[instate[10]] ^ ISbox[instate[7]];
	tmp = Xtime(tmp);
	tmp = Xtime(tmp);
	tmp = Xtime(tmp);
	tmp = tmp ^ ISbox[instate[0]] ^ ISbox[instate[13]] ^ ISbox[instate[10]] ^ ISbox[instate[7]];
	/**************************************step1*******************************************/
	step1 = ISbox[instate[0]] ^ ISbox[instate[10]];
	step1 = Xtime(step1);
	step1 = Xtime(step1);
	/******************************************************/
	step2 = ISbox[instate[0]] ^ ISbox[instate[13]];
	step2 = Xtime(step2);
	outstate[0] = (step1 ^ step2 ^ tmp ^ ISbox[instate[0]]) ^ rkey[0];
	/**************************************step2*******************************************/
	step3 = ISbox[instate[13]] ^ ISbox[instate[7]];
	step3 = Xtime(step3);
	step3 = Xtime(step3);
	/*****************************************************/
	step2 = ISbox[instate[13]] ^ ISbox[instate[10]];
	step2 = Xtime(step2);
	outstate[1] = (step3 ^ step2 ^ tmp ^ ISbox[instate[13]]) ^ rkey[1];
	/**************************************step3*******************************************/
	step2 = ISbox[instate[10]] ^ ISbox[instate[7]];
	step2 = Xtime(step2);
	outstate[2] = (step1 ^ step2 ^ tmp ^ ISbox[instate[10]]) ^ rkey[2];
	/**************************************step4*******************************************/
	step2 = ISbox[instate[7]] ^ ISbox[instate[0]];
	step2 = Xtime(step2);
	outstate[3] = (step3 ^ step2 ^ tmp ^ ISbox[instate[7]]) ^ rkey[3];

	///////////////////////////////////////////////////////////////////////////////////////////////////

	tmp = ISbox[instate[4]] ^ ISbox[instate[1]] ^ ISbox[instate[14]] ^ ISbox[instate[11]];
	tmp = Xtime(tmp);
	tmp = Xtime(tmp);
	tmp = Xtime(tmp);
	tmp = tmp ^ ISbox[instate[4]] ^ ISbox[instate[1]] ^ ISbox[instate[14]] ^ ISbox[instate[11]];
	/**************************************step1*******************************************/
	step1 = ISbox[instate[4]] ^ ISbox[instate[14]];
	step1 = Xtime(step1);
	step1 = Xtime(step1);
	/******************************************************/
	step2 = ISbox[instate[4]] ^ ISbox[instate[1]];
	step2 = Xtime(step2);
	outstate[4] = (step1 ^ step2 ^ tmp ^ ISbox[instate[4]]) ^ rkey[4];
	/**************************************step2*******************************************/
	step3 = ISbox[instate[1]] ^ ISbox[instate[11]];
	step3 = Xtime(step3);
	step3 = Xtime(step3);
	/*****************************************************/
	step2 = ISbox[instate[1]] ^ ISbox[instate[14]];
	step2 = Xtime(step2);
	outstate[5] = (step3 ^ step2 ^ tmp ^ ISbox[instate[1]]) ^ rkey[5];
	/**************************************step3*******************************************/
	step2 = ISbox[instate[14]] ^ ISbox[instate[11]];
	step2 = Xtime(step2);
	outstate[6] = (step1 ^ step2 ^ tmp ^ ISbox[instate[14]]) ^ rkey[6];
	/**************************************step4*******************************************/
	step2 = ISbox[instate[11]] ^ ISbox[instate[4]];
	step2 = Xtime(step2);
	outstate[7] = (step3 ^ step2 ^ tmp ^ ISbox[instate[11]]) ^ rkey[7];

	///////////////////////////////////////////////////////////////////////////////////////////////////

	tmp = ISbox[instate[8]] ^ ISbox[instate[5]] ^ ISbox[instate[2]] ^ ISbox[instate[15]];
	tmp = Xtime(tmp);
	tmp = Xtime(tmp);
	tmp = Xtime(tmp);
	tmp = tmp ^ ISbox[instate[8]] ^ ISbox[instate[5]] ^ ISbox[instate[2]] ^ ISbox[instate[15]];
	/**************************************step1*******************************************/
	step1 = ISbox[instate[8]] ^ ISbox[instate[2]];
	step1 = Xtime(step1);
	step1 = Xtime(step1);
	/******************************************************/
	step2 = ISbox[instate[8]] ^ ISbox[instate[5]];
	step2 = Xtime(step2);
	outstate[8] = (step1 ^ step2 ^ tmp ^ ISbox[instate[8]]) ^ rkey[8];
	/**************************************step2*******************************************/
	step3 = ISbox[instate[5]] ^ ISbox[instate[15]];
	step3 = Xtime(step3);
	step3 = Xtime(step3);
	/*****************************************************/
	step2 = ISbox[instate[5]] ^ ISbox[instate[2]];
	step2 = Xtime(step2);
	outstate[9] = (step3 ^ step2 ^ tmp ^ ISbox[instate[5]]) ^ rkey[9];
	/**************************************step3*******************************************/
	step2 = ISbox[instate[2]] ^ ISbox[instate[15]];
	step2 = Xtime(step2);
	outstate[10] = (step1 ^ step2 ^ tmp ^ ISbox[instate[2]]) ^ rkey[10];
	/**************************************step4*******************************************/
	step2 = ISbox[instate[15]] ^ ISbox[instate[8]];
	step2 = Xtime(step2);
	outstate[11] =( step3 ^ step2 ^ tmp ^ ISbox[instate[15]]) ^ rkey[11];

	///////////////////////////////////////////////////////////////////////////////////////////////////

	tmp = ISbox[instate[12]] ^ ISbox[instate[9]] ^ ISbox[instate[6]] ^ ISbox[instate[3]];
	tmp = Xtime(tmp);
	tmp = Xtime(tmp);
	tmp = Xtime(tmp);
	tmp = tmp ^ ISbox[instate[12]] ^ ISbox[instate[9]] ^ ISbox[instate[6]] ^ ISbox[instate[3]];
	/**************************************step1*******************************************/
	step1 = ISbox[instate[12]] ^ ISbox[instate[6]];
	step1 = Xtime(step1);
	step1 = Xtime(step1);
	/******************************************************/
	step2 = ISbox[instate[12]] ^ ISbox[instate[9]];
	step2 = Xtime(step2);
	outstate[12] = (step1 ^ step2 ^ tmp ^ ISbox[instate[12]]) ^ rkey[12];
	/**************************************step2*******************************************/
	step3 = ISbox[instate[9]] ^ ISbox[instate[3]];
	step3 = Xtime(step3);
	step3 = Xtime(step3);
	/*****************************************************/
	step2 = ISbox[instate[9]] ^ ISbox[instate[6]];
	step2 = Xtime(step2);
	outstate[13] = (step3 ^ step2 ^ tmp ^ ISbox[instate[9]]) ^ rkey[13];
	/**************************************step3*******************************************/
	step2 = ISbox[instate[6]] ^ ISbox[instate[3]];
	step2 = Xtime(step2);
	outstate[14] = (step1 ^ step2 ^ tmp ^ ISbox[instate[6]]) ^ rkey[14];
	/**************************************step4*******************************************/
	step2 = ISbox[instate[3]] ^ ISbox[instate[12]];
	step2 = Xtime(step2);
	outstate[15] = (step3 ^ step2 ^ tmp ^ ISbox[instate[3]]) ^ rkey[15];

}

void AES_DEC(unsigned char* ciphertext, unsigned char* plaintext, unsigned char* key)
{
	unsigned char instate[16] = { 0, }; //16byte
	unsigned char outstate[16] = { 0, }; //16byte
	unsigned char keyschedule[176] = { 0, }; //176byte
	unsigned char rkey[16] = { 0, }; //16byte


	KeyExpansion(key, keyschedule, 10);

	instate[0] = ciphertext[0] ^ keyschedule[160]; instate[1] = ciphertext[1] ^ keyschedule[161]; instate[2] = ciphertext[2] ^ keyschedule[162]; instate[3] = ciphertext[3] ^ keyschedule[163];
	instate[4] = ciphertext[4] ^ keyschedule[164]; instate[5] = ciphertext[5] ^ keyschedule[165]; instate[6] = ciphertext[6] ^ keyschedule[166]; instate[7] = ciphertext[7] ^ keyschedule[167];
	instate[8] = ciphertext[8] ^ keyschedule[168]; instate[9] = ciphertext[9] ^ keyschedule[169]; instate[10] = ciphertext[10] ^ keyschedule[170]; instate[11] = ciphertext[11] ^ keyschedule[171];
	instate[12] = ciphertext[12] ^ keyschedule[172]; instate[13] = ciphertext[13] ^ keyschedule[173]; instate[14] = ciphertext[14] ^ keyschedule[174]; instate[15] = ciphertext[15] ^ keyschedule[175];

	rkey[0] = keyschedule[144]; rkey[1] = keyschedule[145]; rkey[2] = keyschedule[146]; rkey[3] = keyschedule[147];
	rkey[4] = keyschedule[148]; rkey[5] = keyschedule[149]; rkey[6] = keyschedule[150]; rkey[7] = keyschedule[151];
	rkey[8] = keyschedule[152]; rkey[9] = keyschedule[153]; rkey[10] = keyschedule[154]; rkey[11] = keyschedule[155];
	rkey[12] = keyschedule[156]; rkey[13] = keyschedule[157]; rkey[14] = keyschedule[158]; rkey[15] = keyschedule[159];
	AES_DEC_fun(instate, outstate, rkey);

	rkey[0] = keyschedule[128]; rkey[1] = keyschedule[129]; rkey[2] = keyschedule[130]; rkey[3] = keyschedule[131];
	rkey[4] = keyschedule[132]; rkey[5] = keyschedule[133]; rkey[6] = keyschedule[134]; rkey[7] = keyschedule[135];
	rkey[8] = keyschedule[136]; rkey[9] = keyschedule[137]; rkey[10] = keyschedule[138]; rkey[11] = keyschedule[139];
	rkey[12] = keyschedule[140]; rkey[13] = keyschedule[141]; rkey[14] = keyschedule[142]; rkey[15] = keyschedule[143];
	AES_DEC_fun(outstate, instate, rkey);

	rkey[0] = keyschedule[112]; rkey[1] = keyschedule[113]; rkey[2] = keyschedule[114]; rkey[3] = keyschedule[115];
	rkey[4] = keyschedule[116]; rkey[5] = keyschedule[117]; rkey[6] = keyschedule[118]; rkey[7] = keyschedule[119];
	rkey[8] = keyschedule[120]; rkey[9] = keyschedule[121]; rkey[10] = keyschedule[122]; rkey[11] = keyschedule[123];
	rkey[12] = keyschedule[124]; rkey[13] = keyschedule[125]; rkey[14] = keyschedule[126]; rkey[15] = keyschedule[127];
	AES_DEC_fun(instate, outstate, rkey);

	rkey[0] = keyschedule[96]; rkey[1] = keyschedule[97]; rkey[2] = keyschedule[98]; rkey[3] = keyschedule[99];
	rkey[4] = keyschedule[100]; rkey[5] = keyschedule[101]; rkey[6] = keyschedule[102]; rkey[7] = keyschedule[103];
	rkey[8] = keyschedule[104]; rkey[9] = keyschedule[105]; rkey[10] = keyschedule[106]; rkey[11] = keyschedule[107];
	rkey[12] = keyschedule[108]; rkey[13] = keyschedule[109]; rkey[14] = keyschedule[110]; rkey[15] = keyschedule[111];
	AES_DEC_fun(outstate, instate, rkey);

	rkey[0] = keyschedule[80]; rkey[1] = keyschedule[81]; rkey[2] = keyschedule[82]; rkey[3] = keyschedule[83];
	rkey[4] = keyschedule[84]; rkey[5] = keyschedule[85]; rkey[6] = keyschedule[86]; rkey[7] = keyschedule[87];
	rkey[8] = keyschedule[88]; rkey[9] = keyschedule[89]; rkey[10] = keyschedule[90]; rkey[11] = keyschedule[91];
	rkey[12] = keyschedule[92]; rkey[13] = keyschedule[93]; rkey[14] = keyschedule[94]; rkey[15] = keyschedule[95];
	AES_DEC_fun(instate, outstate, rkey);

	rkey[0] = keyschedule[64]; rkey[1] = keyschedule[65]; rkey[2] = keyschedule[66]; rkey[3] = keyschedule[67];
	rkey[4] = keyschedule[68]; rkey[5] = keyschedule[69]; rkey[6] = keyschedule[70]; rkey[7] = keyschedule[71];
	rkey[8] = keyschedule[72]; rkey[9] = keyschedule[73]; rkey[10] = keyschedule[74]; rkey[11] = keyschedule[75];
	rkey[12] = keyschedule[76]; rkey[13] = keyschedule[77]; rkey[14] = keyschedule[78]; rkey[15] = keyschedule[79];
	AES_DEC_fun(outstate, instate, rkey);

	rkey[0] = keyschedule[48]; rkey[1] = keyschedule[49]; rkey[2] = keyschedule[50]; rkey[3] = keyschedule[51];
	rkey[4] = keyschedule[52]; rkey[5] = keyschedule[53]; rkey[6] = keyschedule[54]; rkey[7] = keyschedule[55];
	rkey[8] = keyschedule[56]; rkey[9] = keyschedule[57]; rkey[10] = keyschedule[58]; rkey[11] = keyschedule[59];
	rkey[12] = keyschedule[60]; rkey[13] = keyschedule[61]; rkey[14] = keyschedule[62]; rkey[15] = keyschedule[63];
	AES_DEC_fun(instate, outstate, rkey);

	rkey[0] = keyschedule[32]; rkey[1] = keyschedule[33]; rkey[2] = keyschedule[34]; rkey[3] = keyschedule[35];
	rkey[4] = keyschedule[36]; rkey[5] = keyschedule[37]; rkey[6] = keyschedule[38]; rkey[7] = keyschedule[39];
	rkey[8] = keyschedule[40]; rkey[9] = keyschedule[41]; rkey[10] = keyschedule[42]; rkey[11] = keyschedule[43];
	rkey[12] = keyschedule[44]; rkey[13] = keyschedule[45]; rkey[14] = keyschedule[46]; rkey[15] = keyschedule[47];
	AES_DEC_fun(outstate, instate, rkey);

	rkey[0] = keyschedule[16]; rkey[1] = keyschedule[17]; rkey[2] = keyschedule[18]; rkey[3] = keyschedule[19];
	rkey[4] = keyschedule[20]; rkey[5] = keyschedule[21]; rkey[6] = keyschedule[22]; rkey[7] = keyschedule[23];
	rkey[8] = keyschedule[24]; rkey[9] = keyschedule[25]; rkey[10] = keyschedule[26]; rkey[11] = keyschedule[27];
	rkey[12] = keyschedule[28]; rkey[13] = keyschedule[29]; rkey[14] = keyschedule[30]; rkey[15] = keyschedule[31];
	AES_DEC_fun(instate, outstate, rkey);

	plaintext[0] = ISbox[outstate[0]] ^ key[0]; plaintext[1] = ISbox[outstate[13]] ^ key[1]; plaintext[2] = ISbox[outstate[10]] ^ key[2]; plaintext[3] = ISbox[outstate[7]] ^ key[3];
	plaintext[4] = ISbox[outstate[4]] ^ key[4]; plaintext[5] = ISbox[outstate[1]] ^ key[5]; plaintext[6] = ISbox[outstate[14]] ^ key[6]; plaintext[7] = ISbox[outstate[11]] ^ key[7];
	plaintext[8] = ISbox[outstate[8]] ^ key[8]; plaintext[9] = ISbox[outstate[5]] ^ key[9]; plaintext[10] = ISbox[outstate[2]] ^ key[10]; plaintext[11] = ISbox[outstate[15]] ^ key[11];
	plaintext[12] = ISbox[outstate[12]] ^ key[12]; plaintext[13] = ISbox[outstate[9]] ^ key[13]; plaintext[14] = ISbox[outstate[6]] ^ key[14]; plaintext[15] = ISbox[outstate[3]] ^ key[15];

}
