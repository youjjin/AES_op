#include "AES.h"

//각 모드에 대한 길이 정보를 파일 i/o에서 받아 가져오기

void Xor16byte(unsigned char* instate1, unsigned char* instate2, unsigned char* outstate)
{

	outstate[0] = instate1[0] ^ instate2[0];
	outstate[1] = instate1[1] ^ instate2[1];
	outstate[2] = instate1[2] ^ instate2[2];
	outstate[3] = instate1[3] ^ instate2[3];

	outstate[4] = instate1[4] ^ instate2[4];
	outstate[5] = instate1[5] ^ instate2[5];
	outstate[6] = instate1[6] ^ instate2[6];
	outstate[7] = instate1[7] ^ instate2[7];

	outstate[8] = instate1[8] ^ instate2[8];
	outstate[9] = instate1[9] ^ instate2[9];
	outstate[10] = instate1[10] ^ instate2[10];
	outstate[11] = instate1[11] ^ instate2[11];

	outstate[12] = instate1[12] ^ instate2[12];
	outstate[13] = instate1[13] ^ instate2[13];
	outstate[14] = instate1[14] ^ instate2[14];
	outstate[15] = instate1[15] ^ instate2[15];


}

void CTR_SUM(unsigned char* instate, unsigned char* outstate) //CTR+1해주는 함수
{
	int i = 15, j;
	unsigned int sum = 0;

	sum = instate[i] + 0x01;

	while (i >= 0)
	{
		if (sum > 0xff)
		{
			outstate[i] = sum & 0xff;
			i--;
			sum = instate[i] + 0x01;
		}
		else
		{
			outstate[i] = sum & 0xff;
			break;
		}
	}

	for (j = 0; j < i; j++)
	{
		outstate[j] = instate[j];
	}

}

/************************************KAT & MMT***********************************************/

void ECB(unsigned char* pt, unsigned char* key, unsigned char* ct, unsigned int ptlen)
{
	// AES = 16byte 입출력
	int i=0, j, len, q, r;

	unsigned char p_block[16] = { 0, };
	unsigned char c_block[16] = { 0, };

	len = ptlen;
	q = len / 16;
	r = len % 16;

	while (i < q)
	{
		//memcpy(p_block, pt + i * 16, 16);
		//memcpy보다 이게 더 빠르다...
		p_block[0] = pt[i * 16 + 0];
		p_block[1] = pt[i * 16 + 1];
		p_block[2] = pt[i * 16 + 2];
		p_block[3] = pt[i * 16 + 3];

		p_block[4] = pt[i * 16 + 4];
		p_block[5] = pt[i * 16 + 5];
		p_block[6] = pt[i * 16 + 6];
		p_block[7] = pt[i * 16 + 7];

		p_block[8] = pt[i * 16 + 8];
		p_block[9] = pt[i * 16 + 9];
		p_block[10] = pt[i * 16 + 10];
		p_block[11] = pt[i * 16 + 11];

		p_block[12] = pt[i * 16 + 12];
		p_block[13] = pt[i * 16 + 13];
		p_block[14] = pt[i * 16 + 14];
		p_block[15] = pt[i * 16 + 15];

		/*암호화*/
		AES_ENC(p_block, c_block, key);

		//memcpy(ct + i * 16, c_block, 16);
		ct[i * 16 + 0] = c_block[0];
		ct[i * 16 + 1] = c_block[1];
		ct[i * 16 + 2] = c_block[2];
		ct[i * 16 + 3] = c_block[3];

		ct[i * 16 + 4] = c_block[4];
		ct[i * 16 + 5] = c_block[5];
		ct[i * 16 + 6] = c_block[6];
		ct[i * 16 + 7] = c_block[7];

		ct[i * 16 + 8] = c_block[8];
		ct[i * 16 + 9] = c_block[9];
		ct[i * 16 + 10] = c_block[10];
		ct[i * 16 + 11] = c_block[11];

		ct[i * 16 + 12] = c_block[12];
		ct[i * 16 + 13] = c_block[13];
		ct[i * 16 + 14] = c_block[14];
		ct[i * 16 + 15] = c_block[15];

		i++;
	}
	
}

void CBC(unsigned char* pt, unsigned char* key, unsigned char* ct, unsigned char* iv, unsigned int ptlen)
{
	// AES = 16byte 입출력
	int i = 0, len, q, r;
	unsigned char p_block[16] = { 0, };
	unsigned char c_block[16] = { 0, };
	unsigned char iv_block[16] = { 0, };

	len = ptlen;
	q = len / 16;
	r = len % 16;

	memcpy(iv_block, iv, 16);

	while (i < q)
	{
		//memcpy(p_block, pt + i * 16, 16);
		p_block[0] = pt[i * 16 + 0];
		p_block[1] = pt[i * 16 + 1];
		p_block[2] = pt[i * 16 + 2];
		p_block[3] = pt[i * 16 + 3];

		p_block[4] = pt[i * 16 + 4];
		p_block[5] = pt[i * 16 + 5];
		p_block[6] = pt[i * 16 + 6];
		p_block[7] = pt[i * 16 + 7];

		p_block[8] = pt[i * 16 + 8];
		p_block[9] = pt[i * 16 + 9];
		p_block[10] = pt[i * 16 + 10];
		p_block[11] = pt[i * 16 + 11];

		p_block[12] = pt[i * 16 + 12];
		p_block[13] = pt[i * 16 + 13];
		p_block[14] = pt[i * 16 + 14];
		p_block[15] = pt[i * 16 + 15];

		Xor16byte(iv_block, p_block, p_block);
		AES_ENC(p_block, c_block, key);
		memcpy(iv_block, c_block, 16);

		//memcpy(ct + i * 16, c_block, 16);
		ct[i * 16 + 0] = c_block[0];
		ct[i * 16 + 1] = c_block[1];
		ct[i * 16 + 2] = c_block[2];
		ct[i * 16 + 3] = c_block[3];

		ct[i * 16 + 4] = c_block[4];
		ct[i * 16 + 5] = c_block[5];
		ct[i * 16 + 6] = c_block[6];
		ct[i * 16 + 7] = c_block[7];

		ct[i * 16 + 8] = c_block[8];
		ct[i * 16 + 9] = c_block[9];
		ct[i * 16 + 10] = c_block[10];
		ct[i * 16 + 11] = c_block[11];

		ct[i * 16 + 12] = c_block[12];
		ct[i * 16 + 13] = c_block[13];
		ct[i * 16 + 14] = c_block[14];
		ct[i * 16 + 15] = c_block[15];

		i++;
	}
}

void CTR(unsigned char* pt, unsigned char* key, unsigned char* ct, unsigned char* iv, unsigned int ptlen)
{
	// AES = 16byte 입출력
	int i = 0, len, q, r;
	unsigned char p_block[16] = { 0, };
	unsigned char c_block[16] = { 0, };
	unsigned char iv_block[16] = { 0, };

	len = ptlen;
	q = len / 16;
	r = len % 16;

	memcpy(iv_block, iv, 16);

	while (i < q)
	{
		AES_ENC(iv_block, c_block, key);
		memcpy(p_block, pt + i * 16, 16);

		Xor16byte(c_block, p_block, c_block);
		memcpy(ct + i * 16, c_block, 16);

		CTR_SUM(iv_block, iv_block);
		i++;
	}
}

/************************************MCT***********************************************/

void MCT_ECB(unsigned char* pt, unsigned char* key, unsigned char* ct, unsigned int ptlen, unsigned int keylen, FILE* fp_rsp)
{
	int i, j, n;

	unsigned char key_set[101][17] = { 0, };
	memcpy(key_set[0], key, keylen);
	unsigned char pt_set[1001][17] = { 0, };
	memcpy(pt_set[0], pt, ptlen);
	unsigned char ct_set[1001][17] = { 0, };

	/********************************************************/

	for (i = 0; i < 100; i++)//99번 실행
	{
		/************************key_set****************************/

		printf("KEY = ");
		for (n = 0; n < keylen; n++)
		{
			printf("%02x", key_set[i][n]);
		}
		printf("\n");

		fprintf(fp_rsp, "KEY = ");
		for (n = 0; n < keylen; n++)
		{
			fprintf(fp_rsp, "%02x", key_set[i][n]);
		}
		fprintf(fp_rsp, "\n");

		/************************pt_set****************************/

		printf("PT = ");
		for (n = 0; n < ptlen; n++)
		{
			printf("%02x", pt_set[0][n]);
		}
		printf("\n");

		fprintf(fp_rsp, "PT = ");
		for (n = 0; n < ptlen; n++)
		{
			fprintf(fp_rsp, "%02x", pt_set[0][n]);
		}
		fprintf(fp_rsp, "\n");

		/******************************************************************/
		for (j = 0; j < 1000; j++)
		{
			AES_ENC(pt_set[j], ct_set[j], key_set[i]); //암호화 (pt_set[999], key_set[0]) = ct_set[999]
			memcpy(pt_set[j + 1], ct_set[j], 16); //pt_set[1000] = ct_set[999]
		}

		/***************************키갱신*******************************/

		key_set[i + 1][0] = key_set[i][0] ^ ct_set[999][0];
		key_set[i + 1][1] = key_set[i][1] ^ ct_set[999][1];
		key_set[i + 1][2] = key_set[i][2] ^ ct_set[999][2];
		key_set[i + 1][3] = key_set[i][3] ^ ct_set[999][3];

		key_set[i + 1][4] = key_set[i][4] ^ ct_set[999][4];
		key_set[i + 1][5] = key_set[i][5] ^ ct_set[999][5];
		key_set[i + 1][6] = key_set[i][6] ^ ct_set[999][6];
		key_set[i + 1][7] = key_set[i][7] ^ ct_set[999][7];

		key_set[i + 1][8] = key_set[i][8] ^ ct_set[999][8];
		key_set[i + 1][9] = key_set[i][9] ^ ct_set[999][9];
		key_set[i + 1][10] = key_set[i][10] ^ ct_set[999][10];
		key_set[i + 1][11] = key_set[i][11] ^ ct_set[999][11];

		key_set[i + 1][12] = key_set[i][12] ^ ct_set[999][12];
		key_set[i + 1][13] = key_set[i][13] ^ ct_set[999][13];
		key_set[i + 1][14] = key_set[i][14] ^ ct_set[999][14];
		key_set[i + 1][15] = key_set[i][15] ^ ct_set[999][15];


		/************************ct_set****************************/

		printf("CT = ");
		for (n = 0; n < ptlen; n++)
		{
			printf("%02x", ct_set[999][n]);
		}
		printf("\n");
		printf("\n");

		//pt_set을 파일에 ct로 써줘야함
		fprintf(fp_rsp, "CT = ");
		for (n = 0; n < ptlen; n++)
		{
			fprintf(fp_rsp, "%02x", ct_set[999][n]);
		}
		fprintf(fp_rsp, "\n");
		fprintf(fp_rsp, "\n");

		/***********************************************/

		memcpy(pt_set[0], ct_set[999], 16);

	}

}

void MCT_CBC(unsigned char* pt, unsigned char* key, unsigned char* ct, unsigned char* iv, unsigned int ptlen, unsigned int keylen, unsigned int ivlen, FILE* fp_rsp)
{
	int i, j, n;

	unsigned char key_set[101][17] = { 0, };
	memcpy(key_set[0], key, keylen);
	unsigned char iv_set[101][17] = { 0, };
	memcpy(iv_set[0], iv, ivlen);
	unsigned char pt_set[1001][17] = { 0, };
	memcpy(pt_set[0], pt, ptlen);
	unsigned char ct_set[1001][17] = { 0, };
	unsigned char tmp_set[17] = { 0, };

	/********************************************************/

	for (i = 0; i < 100; i++)//99번 실행
	{
		printf("COUNT = %d\n", i);
		fprintf(fp_rsp, "COUNT = %d\n", i);
		/************************key_set****************************/

		printf("KEY = ");
		for (n = 0; n < keylen; n++)
		{
			printf("%02x", key_set[i][n]);
		}
		printf("\n");

		fprintf(fp_rsp, "KEY = ");
		for (n = 0; n < keylen; n++)
		{
			fprintf(fp_rsp, "%02x", key_set[i][n]);
		}
		fprintf(fp_rsp, "\n");

		/************************iv_set****************************/

		printf("IV = ");
		for (n = 0; n < ivlen; n++)
		{
			printf("%02x", iv_set[i][n]);
		}
		printf("\n");

		fprintf(fp_rsp, "IV = ");
		for (n = 0; n < ivlen; n++)
		{
			fprintf(fp_rsp, "%02x", iv_set[i][n]);
		}
		fprintf(fp_rsp, "\n");

		/************************pt_set****************************/

		printf("PT = ");
		for (n = 0; n < ptlen; n++)
		{
			printf("%02x", pt_set[0][n]);
		}
		printf("\n");

		fprintf(fp_rsp, "PT = ");
		for (n = 0; n < ptlen; n++)
		{
			fprintf(fp_rsp, "%02x", pt_set[0][n]);
		}
		fprintf(fp_rsp, "\n");

		/********************************************************************/

		tmp_set[0] = pt_set[0][0] ^ iv_set[i][0];
		tmp_set[1] = pt_set[0][1] ^ iv_set[i][1];
		tmp_set[2] = pt_set[0][2] ^ iv_set[i][2];
		tmp_set[3] = pt_set[0][3] ^ iv_set[i][3];

		tmp_set[4] = pt_set[0][4] ^ iv_set[i][4];
		tmp_set[5] = pt_set[0][5] ^ iv_set[i][5];
		tmp_set[6] = pt_set[0][6] ^ iv_set[i][6];
		tmp_set[7] = pt_set[0][7] ^ iv_set[i][7];

		tmp_set[8] = pt_set[0][8] ^ iv_set[i][8];
		tmp_set[9] = pt_set[0][9] ^ iv_set[i][9];
		tmp_set[10] = pt_set[0][10] ^ iv_set[i][10];
		tmp_set[11] = pt_set[0][11] ^ iv_set[i][11];

		tmp_set[12] = pt_set[0][12] ^ iv_set[i][12];
		tmp_set[13] = pt_set[0][13] ^ iv_set[i][13];
		tmp_set[14] = pt_set[0][14] ^ iv_set[i][14];
		tmp_set[15] = pt_set[0][15] ^ iv_set[i][15];
		AES_ENC(tmp_set, ct_set[0], key_set[i]);
		memcpy(pt_set[1], iv_set[i], 16);

		for (j = 1; j < 1000; j++)
		{

			tmp_set[0] = pt_set[j][0] ^ ct_set[j - 1][0];
			tmp_set[1] = pt_set[j][1] ^ ct_set[j - 1][1];
			tmp_set[2] = pt_set[j][2] ^ ct_set[j - 1][2];
			tmp_set[3] = pt_set[j][3] ^ ct_set[j - 1][3];

			tmp_set[4] = pt_set[j][4] ^ ct_set[j - 1][4];
			tmp_set[5] = pt_set[j][5] ^ ct_set[j - 1][5];
			tmp_set[6] = pt_set[j][6] ^ ct_set[j - 1][6];
			tmp_set[7] = pt_set[j][7] ^ ct_set[j - 1][7];

			tmp_set[8] = pt_set[j][8] ^ ct_set[j - 1][8];
			tmp_set[9] = pt_set[j][9] ^ ct_set[j - 1][9];
			tmp_set[10] = pt_set[j][10] ^ ct_set[j - 1][10];
			tmp_set[11] = pt_set[j][11] ^ ct_set[j - 1][11];

			tmp_set[12] = pt_set[j][12] ^ ct_set[j - 1][12];
			tmp_set[13] = pt_set[j][13] ^ ct_set[j - 1][13];
			tmp_set[14] = pt_set[j][14] ^ ct_set[j - 1][14];
			tmp_set[15] = pt_set[j][15] ^ ct_set[j - 1][15];

			AES_ENC(tmp_set, ct_set[j], key_set[i]);
			memcpy(pt_set[j + 1], ct_set[j - 1], 16);

		}

		/************************ct_set****************************/

		printf("CT = ");
		for (n = 0; n < ptlen; n++)
		{
			printf("%02x", ct_set[999][n]);
		}
		printf("\n");
		printf("\n");

		//pt_set을 파일에 ct로 써줘야함
		fprintf(fp_rsp, "CT = ");
		for (n = 0; n < ptlen; n++)
		{
			fprintf(fp_rsp, "%02x", ct_set[999][n]);
		}
		fprintf(fp_rsp, "\n");
		fprintf(fp_rsp, "\n");

		/***************************키갱신*******************************/

		key_set[i + 1][0] = key_set[i][0] ^ ct_set[999][0];
		key_set[i + 1][1] = key_set[i][1] ^ ct_set[999][1];
		key_set[i + 1][2] = key_set[i][2] ^ ct_set[999][2];
		key_set[i + 1][3] = key_set[i][3] ^ ct_set[999][3];

		key_set[i + 1][4] = key_set[i][4] ^ ct_set[999][4];
		key_set[i + 1][5] = key_set[i][5] ^ ct_set[999][5];
		key_set[i + 1][6] = key_set[i][6] ^ ct_set[999][6];
		key_set[i + 1][7] = key_set[i][7] ^ ct_set[999][7];

		key_set[i + 1][8] = key_set[i][8] ^ ct_set[999][8];
		key_set[i + 1][9] = key_set[i][9] ^ ct_set[999][9];
		key_set[i + 1][10] = key_set[i][10] ^ ct_set[999][10];
		key_set[i + 1][11] = key_set[i][11] ^ ct_set[999][11];

		key_set[i + 1][12] = key_set[i][12] ^ ct_set[999][12];
		key_set[i + 1][13] = key_set[i][13] ^ ct_set[999][13];
		key_set[i + 1][14] = key_set[i][14] ^ ct_set[999][14];
		key_set[i + 1][15] = key_set[i][15] ^ ct_set[999][15];

		/***********************************************/
		memcpy(iv_set[i + 1], ct_set[999], 16);
		memcpy(pt_set[0], ct_set[998], 16);

	}
}

void MCT_CTR(unsigned char* pt, unsigned char* key, unsigned char* ct, unsigned char* ctr, unsigned int ptlen, unsigned int keylen, unsigned int ctrlen, FILE* fp_rsp)
{
	int i, j, n;

	unsigned char key_set[101][17] = { 0, };
	memcpy(key_set[0], key, keylen);
	unsigned char ctr_set[17] = { 0, };
	memcpy(ctr_set, ctr, ctrlen);
	unsigned char pt_set[1001][17] = { 0, };
	memcpy(pt_set[0], pt, ptlen);
	unsigned char ct_set[1001][17] = { 0, };
	unsigned char tmp_set[17] = { 0, };
	unsigned char out_ctr[17] = { 0, };

	/********************************************************/

	for (i = 0; i < 100; i++)//99번 실행
	{
		printf("COUNT = %d\n", i);
		fprintf(fp_rsp, "COUNT = %d\n", i);
		/************************key_set****************************/

		printf("KEY = ");
		for (n = 0; n < keylen; n++)
		{
			printf("%02x", key_set[i][n]);
		}
		printf("\n");

		fprintf(fp_rsp, "KEY = ");
		for (n = 0; n < keylen; n++)
		{
			fprintf(fp_rsp, "%02x", key_set[i][n]);
		}
		fprintf(fp_rsp, "\n");

		/************************iv_set****************************/

		printf("CTR = ");
		for (n = 0; n < ctrlen; n++)
		{
			printf("%02x", ctr_set[n]);
		}
		printf("\n");

		fprintf(fp_rsp, "CTR = ");
		for (n = 0; n < ctrlen; n++)
		{
			fprintf(fp_rsp, "%02x", ctr_set[n]);
		}
		fprintf(fp_rsp, "\n");

		/************************pt_set****************************/

		printf("PT = ");
		for (n = 0; n < ptlen; n++)
		{
			printf("%02x", pt_set[0][n]);
		}
		printf("\n");

		fprintf(fp_rsp, "PT = ");
		for (n = 0; n < ptlen; n++)
		{
			fprintf(fp_rsp, "%02x", pt_set[0][n]);
		}
		fprintf(fp_rsp, "\n");

		/******************************************************************/

		//memcpy(out_ctr, ctr_set, 16);

		for (j = 0; j < 1000; j++)
		{
			AES_ENC(ctr_set, tmp_set, key_set[i]);

			ct_set[j][0] = pt_set[j][0] ^ tmp_set[0];
			ct_set[j][1] = pt_set[j][1] ^ tmp_set[1];
			ct_set[j][2] = pt_set[j][2] ^ tmp_set[2];
			ct_set[j][3] = pt_set[j][3] ^ tmp_set[3];

			ct_set[j][4] = pt_set[j][4] ^ tmp_set[4];
			ct_set[j][5] = pt_set[j][5] ^ tmp_set[5];
			ct_set[j][6] = pt_set[j][6] ^ tmp_set[6];
			ct_set[j][7] = pt_set[j][7] ^ tmp_set[7];

			ct_set[j][8] = pt_set[j][8] ^ tmp_set[8];
			ct_set[j][9] = pt_set[j][9] ^ tmp_set[9];
			ct_set[j][10] = pt_set[j][10] ^ tmp_set[10];
			ct_set[j][11] = pt_set[j][11] ^ tmp_set[11];

			ct_set[j][12] = pt_set[j][12] ^ tmp_set[12];
			ct_set[j][13] = pt_set[j][13] ^ tmp_set[13];
			ct_set[j][14] = pt_set[j][14] ^ tmp_set[14];
			ct_set[j][15] = pt_set[j][15] ^ tmp_set[15];

			//memcpy(ctr_set, out_ctr, 16);
			CTR_SUM(ctr_set, ctr_set);

			//memcpy(pt_set[j + 1], ct_set[j], 16);
			pt_set[j + 1][0] = ct_set[j][0];
			pt_set[j + 1][1] = ct_set[j][1];
			pt_set[j + 1][2] = ct_set[j][2];
			pt_set[j + 1][3] = ct_set[j][3];

			pt_set[j + 1][4] = ct_set[j][4];
			pt_set[j + 1][5] = ct_set[j][5];
			pt_set[j + 1][6] = ct_set[j][6];
			pt_set[j + 1][7] = ct_set[j][7];

			pt_set[j + 1][8] = ct_set[j][8];
			pt_set[j + 1][9] = ct_set[j][9];
			pt_set[j + 1][10] = ct_set[j][10];
			pt_set[j + 1][11] = ct_set[j][11];

			pt_set[j + 1][12] = ct_set[j][12];
			pt_set[j + 1][13] = ct_set[j][13];
			pt_set[j + 1][14] = ct_set[j][14];
			pt_set[j + 1][15] = ct_set[j][15];


		}
		//ctr_set = ctr_set + 1000
		/************************ct_set****************************/

		printf("CT = ");
		for (n = 0; n < ptlen; n++)
		{
			printf("%02x", ct_set[999][n]);
		}
		printf("\n");
		printf("\n");

		//pt_set을 파일에 ct로 써줘야함
		fprintf(fp_rsp, "CT = ");
		for (n = 0; n < ptlen; n++)
		{
			fprintf(fp_rsp, "%02x", ct_set[999][n]);
		}
		fprintf(fp_rsp, "\n");
		fprintf(fp_rsp, "\n");

		/***************************키갱신*******************************/

		key_set[i + 1][0] = key_set[i][0] ^ ct_set[999][0];
		key_set[i + 1][1] = key_set[i][1] ^ ct_set[999][1];
		key_set[i + 1][2] = key_set[i][2] ^ ct_set[999][2];
		key_set[i + 1][3] = key_set[i][3] ^ ct_set[999][3];

		key_set[i + 1][4] = key_set[i][4] ^ ct_set[999][4];
		key_set[i + 1][5] = key_set[i][5] ^ ct_set[999][5];
		key_set[i + 1][6] = key_set[i][6] ^ ct_set[999][6];
		key_set[i + 1][7] = key_set[i][7] ^ ct_set[999][7];

		key_set[i + 1][8] = key_set[i][8] ^ ct_set[999][8];
		key_set[i + 1][9] = key_set[i][9] ^ ct_set[999][9];
		key_set[i + 1][10] = key_set[i][10] ^ ct_set[999][10];
		key_set[i + 1][11] = key_set[i][11] ^ ct_set[999][11];

		key_set[i + 1][12] = key_set[i][12] ^ ct_set[999][12];
		key_set[i + 1][13] = key_set[i][13] ^ ct_set[999][13];
		key_set[i + 1][14] = key_set[i][14] ^ ct_set[999][14];
		key_set[i + 1][15] = key_set[i][15] ^ ct_set[999][15];

		/***********************************************/

		memcpy(pt_set[0], ct_set[999], 16);

	}
}