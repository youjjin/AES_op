#include "AES.h"

/*********************************************파일 i/o*************************************************/


void Ascii(char* string, unsigned char* stream, int* len)
{
	char seps[] = "=, , \t, \n";//여기서 문제
	char *tok;

	char buf[1000] = { 0, };
	unsigned char buf_2[1000] = { 0, };
	int i = 0, j = 0, cnt = 0, n = 0;
	unsigned char result = 0, six = 0;

	tok = strtok(string, seps);


	while (tok != NULL)
	{
		if (strlen(tok) >= 32)
		{
			*len = strlen(tok) / 2;

			while (j < strlen(tok))
			{
				result = 0;
				six = 0;

				for (i = j; i < j + 2; i++)
				{
					if (isalpha(tok[i]))
					{
						result = toupper(tok[i]) - 55;
						six = six * 16 + result;
					}
					else
					{
						result = tok[i] - 48;
						six = six * 16 + result;
					}
				}

				buf_2[n] = six;
				n++;
				j = j + 2;
			}
		}
		tok = strtok(NULL, seps);
	}

	memcpy(stream, buf_2, sizeof(buf_2));

}

/**************************************KAT*******************************************/

/*******************************ECB_KAT***********************************/

//평문의 길이를 받아주기
//ct를 평문의 길이만큼 동적할당

void ECB_KAT_File_io()
{
	FILE *fp_req;
	FILE *fp_rsp;
	char key_buff[1000];
	char pt_buff[1000];
	char buf[1000];

	int i;
	int* key_len, pt_len;

	char* key_string, pt_string;
	unsigned char key[1000] = { 0, };
	unsigned char pt[1000] = { 0, };
	unsigned char ct[1000] = { 0, };

	fp_req = fopen("AES128(ECB)KAT.req", "r");
	fp_rsp = fopen("AES128(ECB)KAT.rsp", "w");

	if (fp_req == NULL || fp_rsp == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	printf("파일열기 성공\n");
	while (fgets(key_buff, sizeof(key_buff), fp_req) != NULL)
	{
		/******************key******************/

		printf("%s", key_buff);
		fputs(key_buff, fp_rsp);
		//key string 저장하고 16진수로 바꿔주기
		Ascii(key_buff, key, &key_len);
		memset(key_buff, 0, sizeof(key_buff));

		/******************pt******************/

		fgets(pt_buff, sizeof(pt_buff), fp_req);
		printf("%s", pt_buff);
		fputs(pt_buff, fp_rsp);
		//pt stirng저장해서 16진수로 바꾸기
		Ascii(pt_buff, pt, &pt_len);
		memset(pt_buff, 0, sizeof(pt_buff));

		/*****************************************/

		//줄바꿈을 받아주는 buf
		fgets(buf, sizeof(buf), fp_req);
		memset(buf, 0, sizeof(buf));

		/*****************암호화******************/

		ECB(pt, key, ct, pt_len);

		printf("CT = ");
		for (i = 0; i < pt_len; i++)
		{
			printf("%02x", ct[i]);
		}
		printf("\n");
		printf("\n");

		//파일에 써주기
		fprintf(fp_rsp, "CT = ");
		for (i = 0; i < pt_len; i++)
		{
			fprintf(fp_rsp, "%02x", ct[i]);
		}
		fprintf(fp_rsp, "\n");
		fprintf(fp_rsp, "\n");


	}

	fclose(fp_rsp);
	fclose(fp_req);
	printf("END\n");
}

/*******************************CBC_KAT***********************************/

void CBC_KAT_File_io()
{
	FILE *fp_req;
	FILE *fp_rsp;
	char key_buff[1000];
	char iv_buff[1000];
	char pt_buff[1000];
	char buf[1000];

	int i;
	int* key_len, pt_len, iv_len;

	char* key_string, pt_string, iv_string;
	unsigned char key[1000] = { 0, };
	unsigned char iv[1000] = { 0, };
	unsigned char pt[1000] = { 0, };
	unsigned char ct[1000] = { 0, };

	fp_req = fopen("AES128(CBC)KAT.req", "r");
	fp_rsp = fopen("AES128(CBC)KAT.rsp", "w");

	if (fp_req == NULL || fp_rsp == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	printf("파일열기 성공\n");
	while (fgets(key_buff, sizeof(key_buff), fp_req) != NULL)
	{
		/******************key******************/

		printf("%s", key_buff);
		fputs(key_buff, fp_rsp);

		//key string 저장하고 16진수로 바꿔주기
		Ascii(key_buff, key, &key_len);

		memset(key_buff, 0, sizeof(key_buff));

		/******************iv******************/

		fgets(iv_buff, sizeof(iv_buff), fp_req);
		printf("%s", iv_buff);
		fputs(iv_buff, fp_rsp);

		//pt stirng저장해서 16진수로 바꾸기
		Ascii(iv_buff, iv, &iv_len);

		memset(iv_buff, 0, sizeof(iv_buff));

		/******************pt******************/

		fgets(pt_buff, sizeof(pt_buff), fp_req);
		printf("%s", pt_buff);
		fputs(pt_buff, fp_rsp);

		//pt stirng저장해서 16진수로 바꾸기
		Ascii(pt_buff, pt, &pt_len);

		memset(pt_buff, 0, sizeof(pt_buff));

		/*****************************************/

		//줄바꿈을 받아주는 buf
		fgets(buf, sizeof(buf), fp_req);
		memset(buf, 0, sizeof(buf));

		/*****************암호화******************/

		CBC(pt, key, ct, iv, pt_len);

		printf("CT = ");
		for (i = 0; i < pt_len; i++)
		{
			printf("%02x", ct[i]);
		}
		printf("\n");
		printf("\n");

		//파일에 써주기
		fprintf(fp_rsp, "CT = ");
		for (i = 0; i < pt_len; i++)
		{
			fprintf(fp_rsp, "%02x", ct[i]);
		}
		fprintf(fp_rsp, "\n");
		fprintf(fp_rsp, "\n");


	}

	fclose(fp_rsp);
	fclose(fp_req);
}

/*******************************CTR_KAT***********************************/

void CTR_KAT_File_io()
{
	FILE *fp_req;
	FILE *fp_rsp;
	char key_buff[1000];
	char ctr_buff[1000];
	char pt_buff[1000];
	char buf[1000];

	int i;
	int* key_len, pt_len, ctr_len;

	char* key_string, pt_string, ctr_string;
	unsigned char key[1000] = { 0, };
	unsigned char ctr[1000] = { 0, };
	unsigned char pt[1000] = { 0, };
	unsigned char ct[1000] = { 0, };

	fp_req = fopen("AES128(CTR)KAT.req", "r");
	fp_rsp = fopen("AES128(CTR)KAT.rsp", "w");

	if (fp_req == NULL || fp_rsp == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	printf("파일열기 성공\n");
	while (fgets(key_buff, sizeof(key_buff), fp_req) != NULL)
	{
		/******************key******************/

		printf("%s", key_buff);
		fputs(key_buff, fp_rsp);

		//key string 저장하고 16진수로 바꿔주기
		Ascii(key_buff, key, &key_len);

		memset(key_buff, 0, sizeof(key_buff));

		/******************ctr******************/

		fgets(ctr_buff, sizeof(ctr_buff), fp_req);
		printf("%s", ctr_buff);
		fputs(ctr_buff, fp_rsp);

		//pt stirng저장해서 16진수로 바꾸기
		Ascii(ctr_buff, ctr, &ctr_len);

		memset(ctr_buff, 0, sizeof(ctr_buff));

		/******************pt******************/

		fgets(pt_buff, sizeof(pt_buff), fp_req);
		printf("%s", pt_buff);
		fputs(pt_buff, fp_rsp);

		//pt stirng저장해서 16진수로 바꾸기
		Ascii(pt_buff, pt, &pt_len);

		memset(pt_buff, 0, sizeof(pt_buff));

		/*****************************************/

		//줄바꿈을 받아주는 buf
		fgets(buf, sizeof(buf), fp_req);
		memset(buf, 0, sizeof(buf));

		/*****************암호화******************/

		CTR(pt, key, ct, ctr, pt_len);

		printf("CT = ");
		for (i = 0; i < pt_len; i++)
		{
			printf("%02x", ct[i]);
		}
		printf("\n");
		printf("\n");

		//파일에 써주기
		fprintf(fp_rsp, "CT = ");
		for (i = 0; i < pt_len; i++)
		{
			fprintf(fp_rsp, "%02x", ct[i]);
		}
		fprintf(fp_rsp, "\n");
		fprintf(fp_rsp, "\n");


	}

	fclose(fp_rsp);
	fclose(fp_req);
}

/**************************************MMT*******************************************/

/*******************************ECB_MMT***********************************/

//평문의 길이를 받아주기
//ct를 평문의 길이만큼 동적할당

void ECB_MMT_File_io()
{
	FILE *fp_req;
	FILE *fp_rsp;
	char key_buff[1000];
	char pt_buff[1000];
	char buf[1000];

	int i;
	int* key_len, pt_len;

	char* key_string, pt_string;
	unsigned char key[1000] = { 0, };
	unsigned char pt[1000] = { 0, };
	unsigned char ct[1000] = { 0, };

	fp_req = fopen("AES128(ECB)MMT.req", "r");
	fp_rsp = fopen("AES128(ECB)MMT.rsp", "w");

	if (fp_req == NULL || fp_rsp == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	printf("파일열기 성공\n");
	while (fgets(key_buff, sizeof(key_buff), fp_req) != NULL)
	{
		/******************key******************/

		printf("%s", key_buff);
		fputs(key_buff, fp_rsp);

		//key string 저장하고 16진수로 바꿔주기
		Ascii(key_buff, key, &key_len);

		memset(key_buff, 0, sizeof(key_buff));

		/******************pt******************/

		fgets(pt_buff, sizeof(pt_buff), fp_req);
		printf("%s", pt_buff);
		fputs(pt_buff, fp_rsp);

		//pt stirng저장해서 16진수로 바꾸기
		Ascii(pt_buff, pt, &pt_len);

		memset(pt_buff, 0, sizeof(pt_buff));

		/*****************************************/

		//줄바꿈을 받아주는 buf
		fgets(buf, sizeof(buf), fp_req);
		memset(buf, 0, sizeof(buf));

		/*****************암호화******************/

		ECB(pt, key, ct, pt_len);

		printf("CT = ");
		for (i = 0; i < pt_len; i++)
		{
			printf("%02x", ct[i]);
		}
		printf("\n");
		printf("\n");

		//파일에 써주기
		fprintf(fp_rsp, "CT = ");
		for (i = 0; i < pt_len; i++)
		{
			fprintf(fp_rsp, "%02x", ct[i]);
		}
		fprintf(fp_rsp, "\n");
		fprintf(fp_rsp, "\n");


	}

	fclose(fp_rsp);
	fclose(fp_req);
}

/*******************************CBC_MMT***********************************/

void CBC_MMT_File_io()
{
	FILE *fp_req;
	FILE *fp_rsp;
	char key_buff[1000];
	char iv_buff[1000];
	char pt_buff[1000];
	char buf[1000];

	int i;
	int* key_len, pt_len, iv_len;

	char* key_string, pt_string, iv_string;
	unsigned char key[1000] = { 0, };
	unsigned char iv[1000] = { 0, };
	unsigned char pt[1000] = { 0, };
	unsigned char ct[1000] = { 0, };

	fp_req = fopen("AES128(CBC)MMT.req", "r");
	fp_rsp = fopen("AES128(CBC)MMT.rsp", "w");

	if (fp_req == NULL || fp_rsp == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	printf("파일열기 성공\n");
	while (fgets(key_buff, sizeof(key_buff), fp_req) != NULL)
	{
		/******************key******************/

		printf("%s", key_buff);
		fputs(key_buff, fp_rsp);

		//key string 저장하고 16진수로 바꿔주기
		Ascii(key_buff, key, &key_len);

		memset(key_buff, 0, sizeof(key_buff));

		/******************iv******************/

		fgets(iv_buff, sizeof(iv_buff), fp_req);
		printf("%s", iv_buff);
		fputs(iv_buff, fp_rsp);

		//pt stirng저장해서 16진수로 바꾸기
		Ascii(iv_buff, iv, &iv_len);

		memset(iv_buff, 0, sizeof(iv_buff));

		/******************pt******************/

		fgets(pt_buff, sizeof(pt_buff), fp_req);
		printf("%s", pt_buff);
		fputs(pt_buff, fp_rsp);

		//pt stirng저장해서 16진수로 바꾸기
		Ascii(pt_buff, pt, &pt_len);

		memset(pt_buff, 0, sizeof(pt_buff));

		/*****************************************/

		//줄바꿈을 받아주는 buf
		fgets(buf, sizeof(buf), fp_req);
		memset(buf, 0, sizeof(buf));

		/*****************암호화******************/

		CBC(pt, key, ct, iv, pt_len);

		printf("CT = ");
		for (i = 0; i < pt_len; i++)
		{
			printf("%02x", ct[i]);
		}
		printf("\n");
		printf("\n");

		//파일에 써주기
		fprintf(fp_rsp, "CT = ");
		for (i = 0; i < pt_len; i++)
		{
			fprintf(fp_rsp, "%02x", ct[i]);
		}
		fprintf(fp_rsp, "\n");
		fprintf(fp_rsp, "\n");


	}

	fclose(fp_rsp);
	fclose(fp_req);
}

/*******************************CTR_MMT***********************************/

void CTR_MMT_File_io()
{
	FILE *fp_req;
	FILE *fp_rsp;
	char key_buff[1000];
	char ctr_buff[1000];
	char pt_buff[1000];
	char buf[1000];

	int i;
	int* key_len, pt_len, ctr_len;

	char* key_string, pt_string, ctr_string;
	unsigned char key[1000] = { 0, };
	unsigned char ctr[1000] = { 0, };
	unsigned char pt[1000] = { 0, };
	unsigned char ct[1000] = { 0, };

	fp_req = fopen("AES128(CTR)MMT.req", "r");
	fp_rsp = fopen("AES128(CTR)MMT.rsp", "w");

	if (fp_req == NULL || fp_rsp == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	printf("파일열기 성공\n");
	while (fgets(key_buff, sizeof(key_buff), fp_req) != NULL)
	{
		/******************key******************/

		printf("%s", key_buff);
		fputs(key_buff, fp_rsp);

		//key string 저장하고 16진수로 바꿔주기
		Ascii(key_buff, key, &key_len);

		memset(key_buff, 0, sizeof(key_buff));

		/******************ctr******************/

		fgets(ctr_buff, sizeof(ctr_buff), fp_req);
		printf("%s", ctr_buff);
		fputs(ctr_buff, fp_rsp);

		//pt stirng저장해서 16진수로 바꾸기
		Ascii(ctr_buff, ctr, &ctr_len);

		memset(ctr_buff, 0, sizeof(ctr_buff));

		/******************pt******************/

		fgets(pt_buff, sizeof(pt_buff), fp_req);
		printf("%s", pt_buff);
		fputs(pt_buff, fp_rsp);

		//pt stirng저장해서 16진수로 바꾸기
		Ascii(pt_buff, pt, &pt_len);

		memset(pt_buff, 0, sizeof(pt_buff));

		/*****************************************/

		//줄바꿈을 받아주는 buf
		fgets(buf, sizeof(buf), fp_req);
		memset(buf, 0, sizeof(buf));

		/*****************암호화******************/

		CTR(pt, key, ct, ctr, pt_len);

		printf("CT = ");
		for (i = 0; i < pt_len; i++)
		{
			printf("%02x", ct[i]);
		}
		printf("\n");
		printf("\n");

		//파일에 써주기
		fprintf(fp_rsp, "CT = ");
		for (i = 0; i < pt_len; i++)
		{
			fprintf(fp_rsp, "%02x", ct[i]);
		}
		fprintf(fp_rsp, "\n");
		fprintf(fp_rsp, "\n");


	}

	fclose(fp_rsp);
	fclose(fp_req);
}

/**************************************MCT*******************************************/

/*******************************ECB_MCT***********************************/

//평문의 길이를 받아주기
//ct를 평문의 길이만큼 동적할당

void ECB_MCT_File_io()
{
	FILE *fp_req;
	FILE *fp_rsp;
	char key_buff[1000];
	char pt_buff[1000];

	int i;
	int* key_len = NULL, pt_len = NULL;

	char* key_string, pt_string;
	unsigned char key[1000] = { 0, };
	unsigned char pt[1000] = { 0, };
	unsigned char ct[1000] = { 0, };

	fp_req = fopen("AES128(ECB)MCT.req", "r");
	fp_rsp = fopen("AES128(ECB)MCT.rsp", "w");

	if (fp_req == NULL || fp_rsp == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	printf("파일열기 성공\n");
	while (fgets(key_buff, sizeof(key_buff), fp_req) != NULL)
	{
		/******************key******************/

		Ascii(key_buff, key, &key_len);
		memset(key_buff, 0, sizeof(key_buff));

		/******************pt******************/

		fgets(pt_buff, sizeof(pt_buff), fp_req);
		Ascii(pt_buff, pt, &pt_len);
		memset(pt_buff, 0, sizeof(pt_buff));
	}

	/*****************암호화******************/
	MCT_ECB(pt, key, ct, pt_len, key_len, fp_rsp);

	fclose(fp_rsp);
	fclose(fp_req);
}


/*******************************CBC_MCT***********************************/

//평문의 길이를 받아주기
//ct를 평문의 길이만큼 동적할당

void CBC_MCT_File_io()
{
	FILE *fp_req;
	FILE *fp_rsp;
	char key_buff[1000];
	char iv_buff[1000];
	char pt_buff[1000];
	char buf[1000];

	int i;
	int* key_len = NULL, pt_len = NULL, iv_len = NULL;

	char* key_string, pt_string, iv_string;
	unsigned char key[1000] = { 0, };
	unsigned char iv[1000] = { 0, };
	unsigned char pt[1000] = { 0, };
	unsigned char ct[1000] = { 0, };

	fp_req = fopen("AES128(CBC)MCT.req", "r");
	fp_rsp = fopen("AES128(CBC)MCT.rsp", "w");

	if (fp_req == NULL || fp_rsp == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	printf("파일열기 성공\n");
	while (fgets(key_buff, sizeof(key_buff), fp_req) != NULL)
	{
		/******************key******************/

		Ascii(key_buff, key, &key_len);
		memset(key_buff, 0, sizeof(key_buff));

		/******************iv******************/

		fgets(iv_buff, sizeof(iv_buff), fp_req);
		Ascii(iv_buff, iv, &iv_len);
		memset(iv_buff, 0, sizeof(iv_buff));

		/******************pt******************/

		fgets(pt_buff, sizeof(pt_buff), fp_req);
		Ascii(pt_buff, pt, &pt_len);
		memset(pt_buff, 0, sizeof(pt_buff));
	}

	/*****************암호화******************/

	MCT_CBC(pt, key, ct, iv, pt_len, key_len, iv_len, fp_rsp);

	fclose(fp_rsp);
	fclose(fp_req);
}


/*******************************CTR_MCT***********************************/

void CTR_MCT_File_io()
{
	FILE *fp_req;
	FILE *fp_rsp;
	char key_buff[1000];
	char ctr_buff[1000];
	char pt_buff[1000];
	char buf[1000];

	int i;
	int* key_len = NULL, pt_len = NULL, ctr_len = NULL;

	char* key_string, pt_string, ctr_string;
	unsigned char key[1000] = { 0, };
	unsigned char ctr[1000] = { 0, };
	unsigned char pt[1000] = { 0, };
	unsigned char ct[1000] = { 0, };

	fp_req = fopen("AES128(CTR)MCT.req", "r");
	fp_rsp = fopen("AES128(CTR)MCT.rsp", "w");

	if (fp_req == NULL || fp_rsp == NULL)
	{
		printf("파일열기 실패\n");
		return;
	}

	printf("파일열기 성공\n");
	while (fgets(key_buff, sizeof(key_buff), fp_req) != NULL)
	{

		/******************key******************/

		Ascii(key_buff, key, &key_len);
		memset(key_buff, 0, sizeof(key_buff));

		/******************ctr******************/

		fgets(ctr_buff, sizeof(ctr_buff), fp_req);
		Ascii(ctr_buff, ctr, &ctr_len);
		memset(ctr_buff, 0, sizeof(ctr_buff));

		/******************pt******************/

		fgets(pt_buff, sizeof(pt_buff), fp_req);
		Ascii(pt_buff, pt, &pt_len);
		memset(pt_buff, 0, sizeof(pt_buff));
	}

	MCT_CTR(pt, key, ct, ctr, pt_len, key_len, ctr_len, fp_rsp);

	fclose(fp_rsp);
	fclose(fp_req);
}