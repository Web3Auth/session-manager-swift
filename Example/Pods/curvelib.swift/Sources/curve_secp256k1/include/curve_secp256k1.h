#include <stdbool.h>
#include <stdint.h>

#ifndef __curve_secp256k1_H__
#define __curve_secp256k1_H__ // Include guard

    #ifdef __cplusplus // Required for C++ compiler
extern "C" {
    #endif
//Forward Declarations
struct PublicKey;
struct SecretKey;
struct Signature;
struct PublicKeyCollection;
struct EncryptedMessage;

// Version
char * curve_secp256k1_get_version(int *error_code);

// String
void curve_secp256k1_string_free(char *ptr);

// PrivateKey
struct SecretKey * curve_secp256k1_private_key_generate(void);
struct SecretKey * curve_secp256k1_private_key_parse(char *input, int *error_code);
void curve_secp256k1_private_key_tweak_add_assign(struct SecretKey *key, struct SecretKey *tweak, int *error_code);
void curve_secp256k1_private_key_tweak_mul_assign(struct SecretKey *key, struct SecretKey *tweak, int *error_code);
void curve_secp256k1_private_key_inv_assign(struct SecretKey *key, int *error_code);
struct SecretKey * curve_secp256k1_private_key_inv(struct SecretKey *key, int *error_code);
struct PublicKey * curve_secp256k1_private_key_to_public_key(struct SecretKey *key, int *error_code);
char * curve_secp256k1_private_key_serialize(struct SecretKey *key, int *error_code);
void curve_secp256k1_private_key_free(struct SecretKey *key);

// PublicKey
struct PublicKey * curve_secp256k1_public_key_parse(char *input, int *error_code);
char * curve_secp256k1_public_key_serialize(struct PublicKey *key, bool compress, int *error_code);
void curve_secp256k1_public_key_tweak_add_assign(struct PublicKey *key, struct SecretKey *tweak, int *error_code);
void curve_secp256k1_public_key_tweak_mul_assign(struct PublicKey *key, struct SecretKey *tweak, int *error_code);
struct PublicKey * curve_secp256k1_public_key_tweak_mul(struct PublicKey *key, struct SecretKey *tweak, int *error_code);
struct PublicKey * curve_secp256k1_public_key_combine(struct PublicKeyCollection* collection, int *error_code);
void curve_secp256k1_public_key_free(struct PublicKey *key);

// PublicKeyCollection
struct PublicKeyCollection * curve_secp256k1_public_key_collection_new(void);
void curve_secp256k1_public_key_collection_add(struct PublicKeyCollection *collection, struct PublicKey *key, int *error_code);
void curve_secp256k1_public_key_collection_free(struct PublicKeyCollection *collection);

// Signature
struct Signature * curve_secp256k1_ecdsa_signature_parse(char *input, int *error_code);
char * curve_secp256k1_ecdsa_signature_serialize(struct Signature *sig, int *error_code);
char * curve_secp256k1_ecdsa_signature_serialize_der(struct Signature *sig, int *error_code);
void curve_secp256k1_signature_free(struct Signature *signature);

// ECDH
char *curve_secp256k1_ecdh(struct SecretKey *secret_key, struct PublicKey *public_key, int *error_code); // sha256(pk.mul(sk).compress())
char *curve_secp256k1_standard_ecdh(struct SecretKey *secret_key, struct PublicKey *public_key, int *error_code); // Note: This is the standard ecdh which differs from libsecp256k1

// ECDSA
struct Signature * curve_secp256k1_ecdsa_sign_recoverable(struct SecretKey *key, char *hash, int *error_code);
struct PublicKey * curve_secp256k1_ecdsa_recover(struct Signature *signature, char *hash, int *error_code);

// Encryption
struct EncryptedMessage *curve_secp256k1_encrypted_message_from_components(char *ciphertext, struct PublicKey *ephemeral_public_key, char *iv, char *mac,  int* error_code);
char *curve_secp256k1_encrypted_message_get_ciphertext(struct EncryptedMessage *message, int* error_code);
struct PublickKey *curve_secp256k1_encrypted_message_get_ephemeral_public_key(struct EncryptedMessage *message, int* error_code);
char *curve_secp256k1_encrypted_message_get_mac(struct EncryptedMessage *message,int* error_code);
char *curve_secp256k1_encrypted_message_get_iv(struct EncryptedMessage *message,int* error_code);
void curve_secp256k1_encrypted_message_free(struct EncryptedMessage *message);
struct EncryptedMessage *curve_secp256k1_aes_cbc_hmac_encrypt(struct PublicKey *public_key, char *plain_text, int *error_code);
char *curve_secp256k1_aes_cbc_hmac_decrypt(struct SecretKey* secret_key, struct EncryptedMessage* encrypted, bool skip_mac_check, int* error_code );

char *curve_sha3_keccak256(char *hex_data, int *error_code);

    #ifdef __cplusplus
}     // extern "C"
    #endif
#endif // __curve_secp256k1_H__
