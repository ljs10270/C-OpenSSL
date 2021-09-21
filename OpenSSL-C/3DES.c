#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "openssl/applink.c" 

#define NUM_BYTES_READ_TXT 32 // �ؽ�Ʈ ������ ����Ʈ �ִ� ��

int Cryptology(const unsigned char *cecret_key, const unsigned char *iv, FILE *ifp, FILE *ofp, int isEncrypt);

int main() {

	printf("3DES �˰������� ��/��ȣȭ�� ���� �մϴ�.");

	const EVP_CIPHER *algorism = EVP_des_ede3_cbc(); //��ȣȭ�� ���� �˰���� ��� ����
	EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new(); //��ȣȭ ���ؽ�Ʈ, DES�� 16round ���� ��ȣȭ �߰� ������(�˰���, Ű, IV, �е� ��) ������ ���ؽ�Ʈ ����

	if (ctx_enc == NULL) {
		printf("��ȣȭ ���ؽ�Ʈ�� �������� �ʾҽ��ϴ�.\n");
		return -1;
	}

	// ���� ��ȣȭ �˰����� ctx_enc�� ��� �����Ͽ� �ʱ�ȭ, ��ȣȭ �˰��� �ʱ�ȭ �ϱ⿡ 3~5���� �η� ������
	if (!(EVP_EncryptInit_ex(ctx_enc, algorism, NULL, NULL, NULL))) {
		printf("��ȣȭ�� ���� �˰��� �ʱ�ȭ�� ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	printf("\n");
	printf("���� ���Ű1,2,3�� ���� IV1,2,3 ����Ʈ�� �ʱ�ȭ �Ǿ����ϴ�.\n");
	printf("\n");

	//ctx_enc�� ���� ��ȣȭ �˰����� �����ϰ� �ִ�.
	// Ű1, IV1
	unsigned char *cecret_key_1 = (unsigned char*)malloc(EVP_CIPHER_CTX_key_length(ctx_enc));//3DES �˰��� ���� ���Ű ���� ���� �Ҵ�
	unsigned char *iv_1 = (unsigned char*)malloc(EVP_CIPHER_CTX_iv_length(ctx_enc)); //IV, ���� ù ��ϰ� xor �����Ͽ� ��ȣȭ�� ��ų ���� ���� ���� �Ҵ�

	// ���Ű�� DES �˰����� ����(����)��ŭ ������ �־��
	if (!RAND_bytes(cecret_key_1, EVP_CIPHER_CTX_key_length(ctx_enc))) {
		printf("���Ű_1�� ���� ���� ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	// IV�� DES �˰����� ����(����)��ŭ ������ �־��
	if (!RAND_bytes(iv_1, EVP_CIPHER_CTX_iv_length(ctx_enc))) {
		printf("IV_1�� ���� ���� ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	printf("���� ���Ű_1 �� : ");
	for (int i = 0; i < (int)strlen((const char*)cecret_key_1); i++)          //���� ���Ű �� ���
		printf("0x%X ", cecret_key_1[i]);
	printf("\n");

	printf("���� IV_1 �� : ");
	for (int i = 0; i < (int)strlen((const char*)iv_1); i++)          //���� IV�� ���
		printf("0x%X ", iv_1[i]);
	printf("\n");

	// Ű2, IV2
	unsigned char *cecret_key_2 = (unsigned char*)malloc(EVP_CIPHER_CTX_key_length(ctx_enc));//3DES �˰��� ���� ���Ű ���� ���� �Ҵ�
	unsigned char *iv_2 = (unsigned char*)malloc(EVP_CIPHER_CTX_iv_length(ctx_enc)); //IV, ���� ù ��ϰ� xor �����Ͽ� ��ȣȭ�� ��ų ���� ���� ���� �Ҵ�

	// ���Ű�� DES �˰����� ����(����)��ŭ ������ �־��
	if (!RAND_bytes(cecret_key_2, EVP_CIPHER_CTX_key_length(ctx_enc))) {
		printf("���Ű_2�� ���� ���� ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	// IV�� DES �˰����� ����(����)��ŭ ������ �־��
	if (!RAND_bytes(iv_2, EVP_CIPHER_CTX_iv_length(ctx_enc))) {
		printf("IV_2�� ���� ���� ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	printf("���� ���Ű_2 �� : ");
	for (int i = 0; i < (int)strlen((const char*)cecret_key_2); i++)          //���� ���Ű �� ���
		printf("0x%X ", cecret_key_2[i]);
	printf("\n");

	printf("���� IV_2 �� : ");
	for (int i = 0; i < (int)strlen((const char*)iv_2); i++)          //���� IV�� ���
		printf("0x%X ", iv_2[i]);
	printf("\n");

	// Ű3, IV3
	unsigned char *cecret_key_3 = (unsigned char*)malloc(EVP_CIPHER_CTX_key_length(ctx_enc));//3DES �˰��� ���� ���Ű ���� ���� �Ҵ�
	unsigned char *iv_3 = (unsigned char*)malloc(EVP_CIPHER_CTX_iv_length(ctx_enc)); //IV, ���� ù ��ϰ� xor �����Ͽ� ��ȣȭ�� ��ų ���� ���� ���� �Ҵ�

	// ���Ű�� DES �˰����� ����(����)��ŭ ������ �־��
	if (!RAND_bytes(cecret_key_3, EVP_CIPHER_CTX_key_length(ctx_enc))) {
		printf("���Ű_3�� ���� ���� ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	// IV�� DES �˰����� ����(����)��ŭ ������ �־��
	if (!RAND_bytes(iv_3, EVP_CIPHER_CTX_iv_length(ctx_enc))) {
		printf("IV_3�� ���� ���� ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	printf("���� ���Ű_3 �� : ");
	for (int i = 0; i < (int)strlen((const char*)cecret_key_3); i++)          //���� ���Ű �� ���
		printf("0x%X ", cecret_key_3[i]);
	printf("\n");

	printf("���� IV_3 �� : ");
	for (int i = 0; i < (int)strlen((const char*)iv_3); i++)          //���� IV�� ���
		printf("0x%X ", iv_3[i]);
	printf("\n");


	//1. 3DES ��ȣ��_1(cecret_key_1, iv_1 ���), ��ȣ��_2(cecret_key_2, iv_2 ���) ����
	printf("\n");
	printf("�� �ؽ�Ʈ ������ �о� ��ȣ��_1 ������ �����մϴ�.\n");
	printf("\n");

	FILE *pfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/��.txt", "r");
	FILE *cfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/3DES_��ȣ��_1.txt", "w");

	if (pfp == NULL) {
		printf("�� �ؽ�Ʈ ������ �������� �ʽ��ϴ�.\n");
		return -1;
	}

	if (cfp == NULL) {
		printf("��ȣ��_1 �ؽ�Ʈ ���� ������ ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	Cryptology(cecret_key_1, iv_1, pfp, cfp, 1); //��ȣȭ, �� ������ 1�� ��ȣȭ �ϰڴٴ� �ǹ��̴�.
	//������ ������ �Ű������� isEncrypt�ε� 1�̸� ��ȣȭ 0�̸� ��ȣȭ

	fclose(pfp);
	fclose(cfp);

	printf("\n");
	printf("��ȣ��_1 �ؽ�Ʈ ������ �о� ��ȣȭ(��ȣ��_2 ����)�� �����մϴ�.\n");
	printf("\n");

	cfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/3DES_��ȣ��_1.txt", "r");
	pfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/3DES_��ȣ��_2.txt", "w");

	if (cfp == NULL) {
		printf("3DES_��ȣ��_1 �ؽ�Ʈ ������ �������� �ʽ��ϴ�.\n");
		return -1;
	}

	if (pfp == NULL) {
		printf("3DES_��ȣ��_2 �ؽ�Ʈ ���� ������ ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	Cryptology(cecret_key_2, iv_2, cfp, pfp, 0); //��ȣȭ

	fclose(cfp);
	fclose(pfp);


	//2. 3DES ��ȣ��_3(cecret_key_3, iv_3 ���), ��ȣ��_1(cecret_key_3, iv_3 ���) ����
	printf("\n");
	printf("��ȣ��_2�� �о� ��ȣ��_3 ������ �����մϴ�.\n");
	printf("\n");

	pfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/3DES_��ȣ��_2.txt", "r");
	cfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/3DES_��ȣ��_3.txt", "w");

	if (pfp == NULL) {
		printf("3DES_��ȣ��_2 �ؽ�Ʈ ������ �������� �ʽ��ϴ�.\n");
		return -1;
	}

	if (cfp == NULL) {
		printf("3DES_��ȣ��_3 �ؽ�Ʈ ���� ������ ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	Cryptology(cecret_key_3, iv_3, pfp, cfp, 1); //��ȣȭ, �� ������ 1�� ��ȣȭ �ϰڴٴ� �ǹ��̴�.
	//������ ������ �Ű������� isEncrypt�ε� 1�̸� ��ȣȭ 0�̸� ��ȣȭ

	fclose(pfp);
	fclose(cfp);

	printf("\n");
	printf("3DES_��ȣ��_3 �ؽ�Ʈ ������ �о� ��ȣȭ(��ȣ��_1 ����)�� �����մϴ�.\n");
	printf("\n");

	cfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/3DES_��ȣ��_3.txt", "r");
	pfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/3DES_��ȣ��_1.txt", "w");

	if (cfp == NULL) {
		printf("3DES_��ȣ��_3 �ؽ�Ʈ ������ �������� �ʽ��ϴ�.\n");
		return -1;
	}

	if (pfp == NULL) {
		printf("3DES_��ȣ��_1 �ؽ�Ʈ ���� ������ ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	Cryptology(cecret_key_3, iv_3, cfp, pfp, 0); //��ȣȭ

	fclose(cfp);
	fclose(pfp);

	//3. 3DES ��ȣ��_2(cecret_key_2, iv_2 ���), ��ȣ��_3(cecret_key_1, iv_1 ���) ����
	printf("\n");
	printf("��ȣ��_1�� �о� ��ȣ��_2 ������ �����մϴ�.\n");
	printf("\n");

	pfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/3DES_��ȣ��_1.txt", "r");
	cfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/3DES_��ȣ��_2.txt", "w");

	if (pfp == NULL) {
		printf("3DES_��ȣ��_1 �ؽ�Ʈ ������ �������� �ʽ��ϴ�.\n");
		return -1;
	}

	if (cfp == NULL) {
		printf("3DES_��ȣ��_2 �ؽ�Ʈ ���� ������ ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	Cryptology(cecret_key_2, iv_2, pfp, cfp, 1); //��ȣȭ, �� ������ 1�� ��ȣȭ �ϰڴٴ� �ǹ��̴�.
	//������ ������ �Ű������� isEncrypt�ε� 1�̸� ��ȣȭ 0�̸� ��ȣȭ

	fclose(pfp);
	fclose(cfp);

	printf("\n");
	printf("3DES_��ȣ��_2 �ؽ�Ʈ ������ �о� ��ȣȭ(��ȣ��_3 ����)�� �����մϴ�.\n");
	printf("\n");

	cfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/3DES_��ȣ��_2.txt", "r");
	pfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/3DES_��ȣ��_3.txt", "w");

	if (cfp == NULL) {
		printf("3DES_��ȣ��_2 �ؽ�Ʈ ������ �������� �ʽ��ϴ�.\n");
		return -1;
	}

	if (pfp == NULL) {
		printf("3DES_��ȣ��_3 �ؽ�Ʈ ���� ������ ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	Cryptology(cecret_key_1, iv_1, cfp, pfp, 0); //��ȣȭ

	fclose(cfp);
	fclose(pfp);

	return 0;
}

int Cryptology(const unsigned char *cecret_key, const unsigned char *iv, FILE *ifp, FILE *ofp, int isEncrypt) {

	EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new(); //���ؽ�Ʈ ����, DES���� ��ȣȭ�� �ٽ� ��ȣȭ�ϴ� ���̴� enc��� �����̸� ������

	if (ctx_enc == NULL) {
		printf("��/��ȣȭ�� ���� ��ȣȭ ���ؽ�Ʈ�� �������� �ʾҽ��ϴ�.\n");
		return -1;
	}

	//ctx_enc(���ؽ�Ʈ)�� �Ϻ�ȣȭ �˰���, ���Ű, IV, ��ȣȭ���� ��ȣȭ���� ���θ� �ʱ�ȭ �Ѵ�.
	if (!(EVP_CipherInit_ex(ctx_enc, EVP_des_ede3_cbc(), NULL, cecret_key, iv, isEncrypt))) {
		printf("��/��ȣȭ�� ���� ��ȣȭ ���ؽ�Ʈ�� �ʱ�ȭ�� ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	unsigned char *input_buf = (unsigned char*)malloc(NUM_BYTES_READ_TXT); //�Է� ���ۿ� �ִ� ����Ʈ ���� �Ҵ�
	unsigned char *output_buf = (unsigned char*)malloc(NUM_BYTES_READ_TXT + EVP_CIPHER_CTX_block_size(ctx_enc));
	//��� ���ۿ� �ִ� ����Ʈ ������ �е� �۾��� ����, DES�� 8����Ʈ�� ��/��ȣȭ �ϴµ� ���� ������ ����Ʈ�� ä���.

	if (input_buf == NULL) {
		printf("��/��ȣȭ�� ���� ��ǲ ���� �Ҵ� ����\n");
		return -1;
	}

	if (output_buf == NULL) {
		printf("��/��ȣȭ�� ���� �ƿ�ǲ ���� �Ҵ� ����\n");
		return -1;
	}

	int intxtlen = 0; //fread()�� size_t �ڷ����� ��ȯ��(EVP ������ int�� ����) ���� ����Ʈ �� ���� 
	int outtxtlen = 0; //�� ����Ʈ ��ȣȭ/��ȣȭ �ߴ���

	while (1) {
		intxtlen = (int)fread(input_buf, 1, NUM_BYTES_READ_TXT, ifp);
		//ifp(��ȣȭ �Ҷ��� ��, ��ȣȭ �Ҷ��� ��ȣ��).txt ���Ͽ��� �ִ� ����Ʈ ��(#define)�� ���̸�
		// ���� �迭�� 1����Ʈ(������ ũ��)�� �а� input_buf�� ����. ���� ����Ʈ ���� ���ϵ�

		if (intxtlen <= 0)
			break;

		// ���� ����Ʈ ��(���� ũ��)��ŭ input_buf�� �а� DES�̹Ƿ� 8����Ʈ(8�� ���, �е��� ����� ����)�� 
		// ��ȣȭ ���� output_buf�� �ִ´�. ��ȣȭ ��Ų ����Ʈ ���� outtxtlen�� ���� ��. ���������� 1 ��ȯ
		if (1 != EVP_CipherUpdate(ctx_enc, output_buf, &outtxtlen, input_buf, intxtlen)) {
			printf("��ǲ ���ۿ��� �����͸� ��/��ȣȭ �ϴµ� �����Ͽ����ϴ�.\n");
			return -1;
		}

		printf("\n ���� ����Ʈ �� = %d , ��/��ȣȭ�� ����Ʈ �� = %d", intxtlen, outtxtlen);
		printf("\n\n");

	
		// ofp���Ͽ� output_buf �迭�� �����͸� 1����Ʈ�� outtxtlen ��ŭ ����
		fwrite(output_buf, 1, outtxtlen, ofp);

	}


	// ctx_enc�� output_buf�� ������ ��ȣȭ �ߴ��� �˰� �ִ�. 8����Ʈ�� ������
	// ���� ����Ʈ(�е�)�� ���� ��. ���� ����Ʈ(�е�)�� ��ȣȭ �ϰ�
	EVP_CipherFinal(ctx_enc, output_buf, &outtxtlen);

	//ó���� �е��� �ٽ� ����.
	fwrite(output_buf, 1, outtxtlen, ofp);

	printf("\n �е� ó�� ����Ʈ �� = %d \n\n", outtxtlen);


	EVP_CIPHER_CTX_free(ctx_enc); //���ؽ�Ʈ �Ҵ� ����
	free(input_buf); //����
	free(output_buf); //����
	return 0;
}