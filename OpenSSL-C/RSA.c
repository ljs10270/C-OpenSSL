#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define N 2048
#define E 3

int main(int argc, char **argv) {

	// 1. Serialization(공개 키, 개인 키 나누기) 과정
	RSA *keypair = RSA_generate_key(N, E, NULL, NULL);
	//BIO에 각 키 공간 할당
	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	if (keypair == NULL) {
		printf("RSA 키 생성 실패\n");
		return -1;
	}

	if (pri == NULL) {
		printf("BIO에 개인 키 공간 할당 실패\n");
		return -1;
	}

	if (pub == NULL) {
		printf("BIO에 공개 키 공간 할당 실패\n");
		return -1;
	}

	//RSA 구조체 정보를 통해 각 BIO에 할당한 스트림 공간에 각 키 생성하여 저장
	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);

	//BIO 공간 추출하고
	size_t pri_len = BIO_pending(pri);
	size_t pub_len = BIO_pending(pub);

	// char형에 동적 할당, +1은 각 키 문자열로 이용하기 위함
	char *private_Key = malloc(pri_len + 1);
	char *public_key = malloc(pub_len + 1);

	// BIO에 있는 각 키들 char형 변수에 받아옴 
	BIO_read(pri, private_Key, (int)pri_len);
	BIO_read(pub, public_Key, (int)pub_len);

	// 문자열로 만들어 줌
	private_Key[pri_len] = '\0';
	public_Key[pub_len] = '\0';

	printf("\n%s\n%s\n", private_Key, public_Key);

	
	// 2. 공개 키 Deserialization 과정(char public_Key를 RSA *rpub으로)
	// 공개키를 이용하여 암호화
	FILE *ifp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/평문.txt", "r");
	FILE *ofp = fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/RSA_암호문.txt", "w");

	if (ifp == NULL) {
		printf("평문이 존재하지 않습니다.\n");
		return -1;
	}

	if (ofp == NULL) {
		printf("RSA_암호문 생성 실패\n");
		return -1;
	}

	// BIO 구조체인 rpub에 공개 키 길이 만큼 영역을 할당, 두번째 매개변수가 -1이면 첫번째 매개변수의 길이만큼
	BIO *rpub = BIO_new_mem_buf(public_key, -1);

	// 위의 코드로 BIO rpub에 할당 했으니 공개 키를 rpub에 넣어줌 pub_len 길이 만큼
	BIO_write(rpub, public_key, (int)pub_len);

	//최종적으로 RSA 구조체에 키를 넣어야 하니 변수 생성
	RSA *rsa_pubkey = NULL;

	//BIO rpub에서 RSA의 공개키를 추출하여 RSA 구조체에 값 지정
	if (!PEM_read_bio_RSAPublicKey(rpub, &rsa_pubkey, NULL, NULL)) {
		printf("BIO에 있는 공개키를 추출하는데 실패 하였습니다\n");
	}

	// 평문 읽을 인풋 버퍼 생성, 아웃풋 버퍼는 치퍼텍스트가 대신할 것
	// RSA_PKCS1_OAEP_PADDING은 OAEP 형식의 패딩을 의미함
	unsigned char *input_buf = (unsigned char*)malloc(N + RSA_PKCS1_OAEP_PADDING);


	if (input_buf == NULL) {
		printf("암호화를 위한 인풋 버퍼 할당 실패\n");
		return -1;
	}

	int inlen = 0;

	while (1) {

		inlen = (int)fread(input_buf, 1, N, ifp); //평문 읽고

		if (inlen <= 0)
			break;

	}
	printf("\nplaintext = %s\n\n", input_buf);

	// 암호문 변수 만들어 RSA 구조체의 사이즈 만큼 동적 할당
	unsigned char *ciphertxt = (unsigned char*)malloc(RSA_size(rsa_pubkey));

	// 에러 검출을 위해, #include <openssl/err.h>는 어떤 종류의 오류가 발생했는지 자세히 알려준다.
	char *err = (char *)malloc(130);

	int encrypt_len = 0;

	//RSA_public_encrypt() - 암호화를 해주는 함수다.
	//인풋 버퍼(평문)의 길이 만큼 평문을 읽어 RSA 구조체의 공개 키를 이용해 위에서 만들어준 암호문텍스트 변수에 암호화하여 넣어라 
	if ((encrypt_len = RSA_public_encrypt((int)strlen(input_buf) + 1, (unsigned char*)input_buf, ciphertxt, rsa_pubkey, RSA_PKCS1_OAEP_PADDING)) == -1) {
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		fprintf(stderr, "암호화 중 에러 발생 : %s", err);
		printf("암호화 중 에러 발생\n");
		return -1;
	}

	fwrite(ciphertxt, 1, N, ofp); //암호문 생성하고 쓰기

	printf("\n\n암호문은 다음과 같습니다. = %s\n\n", ciphertxt);

	printf("RSA 구조체 사이즈(RSA 구조체의 공개 키 = %d, 길이 = %d, 암호화된 길이 = %d\n", RSA_size(rsa_pubkey), (int)strlen(input_buf), encrypt_len);

	free(input_buf);
	fclose(ifp);
	fclose(ofp);

	
	//2. Deserialization 과정(개인 키 변환)
	//(char* pri ==> RSA *rpri), 복호화
	fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/RSA_암호문.txt", "r");
	fopen("C:/Users/LJS/Desktop/Computer Science/Information Security/RSA_복호문.txt", "w");

	if (ifp == NULL) {
		printf("RSA_암호문 파일이 존재하지 않습니다.\n");
		return -1;
	}

	if (ofp == NULL) {
		printf("RSA_복호문 파일 생성 실패\n");
		return -1;
	}

	// 암호화 떄랑 과정 똑같다. BIO 공간 할당 해주고
	BIO *rpri = BIO_new_mem_buf(private_Key, -1);

	// BIO에 개인키 쓰기
	BIO_write(rpri, private_Key, (int)pri_len);

	// 개인키 저장할 RSA 구조체 선언해주고
	RSA *rsa_prikey = NULL;

	// RSA 구조체에 BIO의 개인키 추출하여 가져오기
	if (!PEM_read_bio_RSAPrivateKey(rpri, &rsa_prikey, NULL, NULL)) {
		printf("BIO에 있는 개인키를 추출하는데 실패 하였습니다\n");
		return -1;
	}

	// 인풋 아웃풋 버퍼 할당
	input_buf = (unsigned char*)malloc(N + RSA_PKCS1_OAEP_PADDING);

	if (input_buf == NULL) {
		printf("복호화를 위한 인풋 버퍼 할당 실패 \n");
		return -1;
	}


	inlen = 0;

	while (1) {

		inlen = (int)fread(input_buf, 1, N, ifp);

		if (inlen <= 0)
			break;

	}

	// 복호문 저장할 변수 선언하고 RSA 구조체의 개인 키 만큼 길이 할당
	unsigned char *decrypt = (unsigned char*)malloc(RSA_size(rsa_prikey));

	int decrypt_len = -1;

	if ((decrypt_len = RSA_private_decrypt(encrypt_len, (unsigned char*)ciphertxt, decrypt, rsa_prikey, RSA_PKCS1_OAEP_PADDING)) == -1) {
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		fprintf(stderr, "복호화 중 오류 발생 : %s\n", err);
		printf("복호화 중 오류 발생\n");
		return -1;
	}

	// 복호문 파일에 쓰기
	fwrite(decrypt, 1, N, ofp);

	printf("RSA사이즈(RSA 구조체의 개인 키 = %d, 개인키 길이 = %d, 암호화 된 길이 = %d\n", RSA_size(rsa_prikey), (int)strlen(ciphertxt), encrypt_len);

	printf("복호화 된 길이 = %d\n\n", decrypt_len);

	printf("복호문: %s\n", decrypt);

	free(input_buf);
	fclose(ifp);
	fclose(ofp);

	return 0;
}