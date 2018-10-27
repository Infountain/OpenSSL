#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/err.h>

void Digest(char *message, const EVP_MD * mech_digest);
int Public_Encrypt();
int Private_Decrypt();
RSA * createRSA(unsigned char * key, int public);
void printLastError(char *msg);

unsigned char message_digest_value[EVP_MAX_MD_SIZE];
int padding= RSA_PKCS1_PADDING;

int main(int argc, char *argv[]) {
	int i,j;
  int mech;
  int mechanism;
	unsigned char encrypted[4098]={};
	unsigned char decrypted[4098]={};
	char message[] = "May the force be with you";
	const EVP_MD *mech_digest;

	if (argc != 3)
	{
		printf("Usage : executable <Public_key_file> <private_key_file>\n");
		exit(0);
	}

  printf("Please enter the digest mechanism:\n");
  printf("1. For SHA256\n");
  printf("2. For SHA512\n");
  scanf("%d",&mech);

  if(mech == 1){
    mechanism = NID_sha256;
  }
  else if(mech == 2){
    mechanism = NID_sha512;
  }
  else{
    printf("BAD CHOICE\n");
    exit(1);
  }

	char *publicKey = NULL;

	FILE *fpublicKey = fopen(argv[1], "rb");

	if( fpublicKey != NULL)
	{
		if (fseek(fpublicKey, 0L, SEEK_END) == 0)
		{
			long pub_buf_size = ftell(fpublicKey);
			if (pub_buf_size == -1)
			{
				exit(0);
			}
			publicKey = malloc(sizeof(char) * (pub_buf_size));

			if (fseek(fpublicKey, 0L, SEEK_SET) != 0) {
				exit(0);
			}
			size_t newLen = fread(publicKey, sizeof(char), pub_buf_size, fpublicKey);
			printf("\npub key is: ");
		         if (newLen == 0) {
		             fputs("Error reading file", stderr);
		         } else {
		             publicKey[newLen] = '\0';
		         }
		}
	}

	char *privateKey = NULL;

	FILE *fprivateKey = fopen(argv[2], "rb");

	if( fprivateKey != NULL)
	{
		if (fseek(fprivateKey, 0L, SEEK_END) == 0)
		{
			long priv_buf_size = ftell(fprivateKey);
			if (priv_buf_size == -1)
			{
				exit(0);
			}
			privateKey = malloc(sizeof(char) * (priv_buf_size));

			if (fseek(fprivateKey, 0L, SEEK_SET) != 0) {
				exit(0);
			}
			size_t newLen = fread(privateKey, sizeof(char), priv_buf_size, fprivateKey);
			printf("\npriv key is: ");
		         if (newLen == 0) {
		             fputs("Error reading file", stderr);
		         } else {
		             privateKey[newLen] = '\0';
		         }
		}
	}

  /* Set digest mechanism */
	mech_digest = EVP_get_digestbynid(mechanism);
  printf("\n************************HASHING****************************\n");

  /* Digest function call*/
	Digest(message, mech_digest);
  printf("************************HASHED*****************************\n");

  /* Encrypting message */
	int encrypted_length = Public_Encrypt(message, strlen(message),publicKey,encrypted);
	if(encrypted_length == -1)
	{
		printLastError("Public Encrypt failed ");
		exit(0);
	}
	printf("Encrypted length =%d",encrypted_length);
	printf("\nenc_data is: ");
	for (i = 0; i < encrypted_length; i++)
		printf("%02x", encrypted[i]);
  printf("\n************************ENCRYPTED**************************\n");

  /* Decrypting the Encrypted Message from previous step */
	int decrypted_length = Private_Decrypt(encrypted,encrypted_length, privateKey, decrypted);
	if(decrypted_length == -1)
	{
		printLastError("Private Decrypt failed ");
		exit(0);
	}
	printf("Decrypted Text =%s\n",decrypted);
	printf("Decrypted Length =%d\n",decrypted_length);
  printf("************************DECRYPTED**************************\n");

	fclose(fpublicKey);
	free(publicKey);

	fclose(fprivateKey);
	free(privateKey);
	return 0;
}
/*
Digest
Parameters : char* message              - Message to be hash_enc_dec
             const EVP_MD * mech_digest - Digest mechanism
*/

void Digest(char *message, const EVP_MD * mech_digest) {
    /* Digest context */
		EVP_MD_CTX *message_digest_ctx;
		int message_digest_length, i;

    /* Initializing the digest context */
		message_digest_ctx = EVP_MD_CTX_new();

    /* Digest Initializing */
		EVP_DigestInit_ex(message_digest_ctx, mech_digest, NULL);

    /* Digest Update -- Can be called multiple times */
		EVP_DigestUpdate(message_digest_ctx, message, strlen(message));

    /* Digest Final -- Digest calculated here */
		EVP_DigestFinal_ex(message_digest_ctx,message_digest_value,&message_digest_length);

    /* Free the context */
		EVP_MD_CTX_free(message_digest_ctx);

		printf("Digest of data is: ");

    /* Just Printing */
		for (i = 0; i < message_digest_length; i++)
			printf("%02x", message_digest_value[i]);
		printf("\n");
}

/*
  Encryption using Public key
  Parameters : unsigned char * data     - data to be ENCRYPTED
               int data_len             - length of the data to be encyrypted
               unsigned char *encrypted - Return encrypted data
*/
int Public_Encrypt(unsigned char * data, int data_len, unsigned char *key, unsigned char *encrypted) {
		RSA * rsa = createRSA(key, 1);
    printf("\n************************ENCRYPTING*************************\n");
		int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
		return result;
}


/*
  Decryption using Private key
  Parameters : unsigned char * data     - data to be DECRYPTED
               int data_len             - length of the data to be Decyrypted
               unsigned char *decrypted - Return decrypted data
*/
int Private_Decrypt(unsigned char * data,int data_len, unsigned char * key, unsigned char *decrypted) {
		RSA * rsa = createRSA(key,0);
    printf("\n************************DECRYPTING*************************\n");
		int result = RSA_private_decrypt(data_len,data,decrypted,rsa,padding);
    return result;
}

RSA * createRSA(unsigned char * key, int public) {
		RSA *rsa = NULL;
		BIO *keyBio;

		keyBio = BIO_new_mem_buf(key,-1);
		if(keyBio == NULL){
			printf("Failed to c reate BIO\n" );
			return 0;
		}
		if(public)
		{
			rsa = PEM_read_bio_RSA_PUBKEY(keyBio, &rsa, NULL, NULL);
		}
		else{
			rsa = PEM_read_bio_RSAPrivateKey(keyBio, &rsa, NULL, NULL);
		}
		if(rsa == NULL)
		{
			printf( "Failed to create RSA");
		}

		return rsa;
}

void printLastError(char *msg) {
		char * err = malloc(130);;
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		printf("%s ERROR: %s\n",msg, err);
		free(err);
}
