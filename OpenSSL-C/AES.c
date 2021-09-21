#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "openssl/applink.c" 

#define NUM_BYTES_READ_TXT 32 // �ؽ�Ʈ ���Ͽ��� 32����Ʈ(256bit)�� ��ȣȭ �� ���̴�.

int Cryptology(const unsigned char *cecret_key, const unsigned char *iv, FILE *ifp, FILE *ofp, int isEncrypt);

int main() {

	printf("AES �˰���(Ű 128bit)���� ��/��ȣȭ�� ���� �մϴ�.");

	const EVP_CIPHER *algorism = EVP_aes_128_cbc(); //��ȣȭ�� ���� �˰���� ��� ����
	EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new(); //��ȣȭ ���ؽ�Ʈ, AES�� 10round(128bit) ���� ��ȣȭ �߰� ������(�˰���, Ű, IV, �е� ��) ������ ���ؽ�Ʈ ����

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
	printf("���� ���Ű�� ���� IV ����Ʈ�� �ʱ�ȭ �Ǿ����ϴ�.\n");
	printf("\n");

	//ctx_enc�� ���� ��ȣȭ �˰����� �����ϰ� �ִ�.
	unsigned char *cecret_key = (unsigned char*)malloc(EVP_CIPHER_CTX_key_length(ctx_enc));//AES �˰��� ���� ���Ű ���� ���� �Ҵ�
	unsigned char *iv = (unsigned char*)malloc(EVP_CIPHER_CTX_iv_length(ctx_enc)); //IV, ���� ù ��ϰ� xor �����Ͽ� ��ȣȭ�� ��ų ���� ���� ���� �Ҵ�

	// ���Ű�� AES�� ���� ���� ��ŭ ������ �־�� (128��Ʈ�̴� 10����)
	if (!RAND_bytes(cecret_key, EVP_CIPHER_CTX_key_length(ctx_enc))) {
		printf("���Ű�� ���� ���� ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	// IV�� AES�� ���� ���� ��ŭ ������ �־�� (128��Ʈ�̴� 10����)
	if (!RAND_bytes(iv, EVP_CIPHER_CTX_iv_length(ctx_enc))) {
		printf("IV�� ���� ���� ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	printf("���� ���Ű �� : ");
	for (int i = 0; i < (int)strlen((const char*)cecret_key); i++)          //���� ���Ű �� ���
		printf("0x%X ", cecret_key[i]);
	printf("\n");

	printf("���� IV �� : ");
	for (int i = 0; i < (int)strlen((const char*)iv); i++)          //���� IV�� ���
		printf("0x%X ", iv[i]);
	printf("\n");


	printf("\n");
	printf("�� �ؽ�Ʈ ������ �о� ��ȣȭ�� �����մϴ�.\n");
	printf("\n");

	FILE *pfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/��.txt", "r");
	FILE *cfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/AES_��ȣ��.txt", "w");


	if (pfp == NULL) {
		printf("�� �ؽ�Ʈ ������ �������� �ʽ��ϴ�.\n");
		return -1;
	}

	if (cfp == NULL) {
		printf("��ȣ�� �ؽ�Ʈ ���� ������ ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	Cryptology(cecret_key, iv, pfp, cfp, 1); //��ȣȭ, �� ������ 1�� ��ȣȭ �ϰڴٴ� �ǹ��̴�.
	//������ ������ �Ű������� isEncrypt�ε� 1�̸� ��ȣȭ 0�̸� ��ȣȭ

	fclose(pfp);
	fclose(cfp);

	printf("\n");
	printf("��ȣ�� �ؽ�Ʈ ������ �о� ��ȣȭ�� �����մϴ�.\n");
	printf("\n");

	cfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/AES_��ȣ��.txt", "r");
	pfp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/AES_��ȣ��.txt", "w");


	if (cfp == NULL) {
		printf("��ȣȭ�� �ؽ�Ʈ ������ �������� �ʽ��ϴ�.\n");
		return -1;
	}

	if (pfp == NULL) {
		printf("��ȣȭ �Ͽ� ���� ���� �ؽ�Ʈ ���� ������ ���� �Ͽ����ϴ�.\n");
		return -1;
	}

	Cryptology(cecret_key, iv, cfp, pfp, 0); //��ȣȭ

	fclose(cfp);
	fclose(pfp);

	return 0;
}

int Cryptology(const unsigned char *cecret_key, const unsigned char *iv, FILE *ifp, FILE *ofp, int isEncrypt) {

	EVP_CIPHER_CTX *ctx_enc = EVP_CIPHER_CTX_new(); //���ؽ�Ʈ ����, ��ĪŰ���� ��ȣȭ�� �ٽ� ��ȣȭ�ϴ� ���̴� enc��� �����̸� ������

	if (ctx_enc == NULL) {
		printf("��/��ȣȭ�� ���� ��ȣȭ ���ؽ�Ʈ�� �������� �ʾҽ��ϴ�.\n");
		return -1;
	}

	//ctx_enc(���ؽ�Ʈ)�� �Ϻ�ȣȭ �˰���, ���Ű, IV, ��ȣȭ���� ��ȣȭ���� ���θ� �ʱ�ȭ �Ѵ�.
	if (!(EVP_CipherInit_ex(ctx_enc, EVP_aes_128_cbc(), NULL, cecret_key, iv, isEncrypt))) {
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