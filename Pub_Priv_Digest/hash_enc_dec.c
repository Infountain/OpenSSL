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
	int i;
  int mech;
  int mechanism;
	unsigned char encrypted[4098]={};
	unsigned char decrypted[4098]={};
	char message[] = "May the force be with you";
	const EVP_MD *mech_digest;

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

	char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
					  "MIIBHTANBgkqhkiG9w0BAQEFAAOCAQoAMIIBBQKB/QMJi9kFtE5qz+wuid2wzhoG\n"\
					  "+Y1avJlpZOf90h6nVqjHo1N33kTTErdl/enfQqAAV5eTvqGdNaGQEC5hXq3WPSXm\n"\
					  "KZ/jH/r8mjT7tihNCzoPcorGGBiRVKEPsh/bPN2yMMhPrBayURGc577YayBhYnfN\n"\
					  "i+ZwENR+4ZS7Fo37FkLRwH597U4gTmb3UD+mOBARdCo/Ncn9zXV0Kgbe1pEpeXzS\n"\
					  "ad0SBsPnUu4eHQGbqVvtXc55cZTnEh7ekGGUYsq3lJMG2HkZaMORspJCt9iakh4d\n"\
					  "TgxQA/9LYWXqrCGj6Up88bU2PUQWAowPUMmcaFkFEUwxq10hIONQFy5hkjECAwEA\n"\
					  "AQ==\n"\
					  "-----END PUBLIC KEY-----\n";

	char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
					   "MIIEiwIBAAKB/QMJi9kFtE5qz+wuid2wzhoG+Y1avJlpZOf90h6nVqjHo1N33kTT\n"\
					   "Erdl/enfQqAAV5eTvqGdNaGQEC5hXq3WPSXmKZ/jH/r8mjT7tihNCzoPcorGGBiR\n"\
					   "VKEPsh/bPN2yMMhPrBayURGc577YayBhYnfNi+ZwENR+4ZS7Fo37FkLRwH597U4g\n"\
					   "Tmb3UD+mOBARdCo/Ncn9zXV0Kgbe1pEpeXzSad0SBsPnUu4eHQGbqVvtXc55cZTn\n"\
					   "Eh7ekGGUYsq3lJMG2HkZaMORspJCt9iakh4dTgxQA/9LYWXqrCGj6Up88bU2PUQW\n"\
					   "AowPUMmcaFkFEUwxq10hIONQFy5hkjECAwEAAQKB/ASyv6D1MfQbRYYSdzB2Tln0\n"\
					   "cBI4SYUFgxFZj63bLDHonrx+r1PHLSyEmEEtGeJmpRfTcw6MIGnKbz1PYSWGQRBe\n"\
					   "+ARbURztoZxTwXKVusgVHRmNU7itFjwOC3s7putIuC0jERAKxVx5WgHcw9lSyv6G\n"\
					   "9eF/eIk7u7ZVsI3v2HodGeHJJy/izkxLdDw2OhqqXy4AAsaSonvasNfuLuA9RTz+\n"\
					   "aUzY8TiL5u8EQuy3aLlAymaQan1dZN28jIiynnqvqejJAoz76Vuw7bKS3xqXJ8cT\n"\
					   "8bqACesn5TgoKFW9toVs7GSInXs6HuYsFXhjnNfiOepYoysstBy0T/FxQQJ/Adph\n"\
					   "Y2YGOiDQ3VJ6hOUWTHTSPv/p/xH4viEAraIJZoKXydfjjtOorN99EJr6YPbtxHdW\n"\
					   "mmGG62zJCHozDkbheOrhMlC4E4M7tYvv3Hf7HdveapmmPnBQXdu1CeshjbpesnmQ\n"\
					   "ISgfS1wQd0trFO+3/kXm+adewTHBJ+KLzwV4VQJ/AaOalVksRHUmyt8tTl1HDgZY\n"\
					   "UnDzXzsUrfVPr3ZR0SqqcN5OhQadZjrTnZCVvHStuzwpCyMGbNoJlalElbqoo7QK\n"\
					   "6XjDvDd+ScEMzWLvXLV73ge2zEsqTzWcmgZopMkv61FQ40ZausSL26/eLed2qzvj\n"\
					   "V1eEhMirLuGiOgX+bQJ/AdlPJCrOeb72Rm0du20LU5uXjq4uXYYj5iftklDDClmw\n"\
					   "cv6JmJ8Mg/e0xBWtTYPydf0QFpbKVClFZ8TtHgiQvOG1cUtibm2Y7KnD1/iKQB95\n"\
					   "CmllmpTbStqFBnFpGAzkoTRzHvH2T217LFu+arRHo1dBfsSE4UPwUghSsGrnxQJ/\n"\
					   "ALV3qjVpjqW3xC8m0ehHTYpy8hyFNF9Bv0YDU1fxZGt2UN/jx2Yn9klksZURHPK9\n"\
					   "G+eVvIpGQhc94+rTjYmvWzUHLxeaVzEMverulXi/GjImwsxFQy8SujTuaDJzWSjl\n"\
					   "P3joaZJItNNBxR3XEbUzvjRlSqW/2wlJ9zl/xmZHNQJ+el6ZaDZlXHVuaBW1RBxc\n"\
					   "M2U/8CNgh1L1nw2SPslbiyXCUYjOojje1KS8hQhDq32etUGkvj8jkkHLhMYHl9p0\n"\
					   "ocqjS7jqVlHtypeRDkzls9Lt7x7OwwsxF5QynDG1wHY02cQcLuqUiEhxRBDyw/HB\n"\
					   "XCIHcAGc7B9WIopAR5+8\n"\
					   "-----END RSA PRIVATE KEY-----\n";

  /* Set digest mechanism */
	mech_digest = EVP_get_digestbynid(mechanism);
  printf("************************HASHING****************************\n");

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
