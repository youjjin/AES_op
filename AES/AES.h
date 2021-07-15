#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

#define Xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

void AES_ENC(unsigned char* plaintext, unsigned char* ciphertext, unsigned char* key);
//void AES_DEC(unsigned char* ciphertext, unsigned char* plaintext, unsigned char* key);

void ECB_KAT_File_io();
void CBC_KAT_File_io();
void CTR_KAT_File_io();
void ECB_MMT_File_io();
void CBC_MMT_File_io();
void CTR_MMT_File_io();
void ECB_MCT_File_io();
void CBC_MCT_File_io();
void CTR_MCT_File_io();