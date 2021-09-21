#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "openssl/applink.c" 
#include "openssl/sha.h" 


int file_sha256(char* hashstr);
void trans_string(unsigned char hash[SHA256_DIGEST_LENGTH], char* output);


int file_sha256(char* hashstr)
{
	//SHA256_DIGEST_LENGTH�� 32 �̴�.
	unsigned char hash[SHA256_DIGEST_LENGTH];
	const int bufSize = 2048;

	SHA256_CTX sha256;

	FILE *file = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/��.txt", "rb");

	if (!file)
	{
		printf("���� ���� ����\n");
		return -1;
	}
	printf("������ ���� �Ǿ����ϴ�. \n\n");

	SHA256_Init(&sha256);
	printf("SHA256 �ʱ�ȭ\n\n");

	int readlen = 0;
	unsigned char* read_buf = (unsigned char*)malloc(bufSize + 1);

	if (!read_buf) return -1;

	//���ۿ� ����
	while ((readlen = fread(read_buf, 1, bufSize, file)))
	{ 
		SHA256_Update(&sha256, read_buf, readlen);
		memset(read_buf, 0x00, bufSize);
	}
	
	SHA256_Final(hash, &sha256);
	
	int i = 0;

	for (i = 0; i < 32; i++)
	{
	  printf("%02X", hash[i]);
	}
	printf("\n\n");
	
	trans_string(hash, hashstr);

	fclose(file);

	if (read_buf)
		free(read_buf);

	return 0;
}

void trans_string(unsigned char hash[SHA256_DIGEST_LENGTH], char* output)
{
	int i = 0;

	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		//sprintf�� ���ڿ��� ��ȯ, ������ ���� ���� �����ϴ�
		//��ȯ�� ����� output�� ����.
		sprintf(output + (i * 2), "%02x", hash[i]);
	}
	output[199] = 0;
}


int main()
{
	char hash_str[200];

	file_sha256(hash_str);

	printf("�ؽ� �� ��\n");
	printf("%s\n", hash_str);
	
	return 0;
}