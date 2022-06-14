#ifndef API_H
#define API_H

/*************************************************
 * Name:        XMSS_crypto_sign_keypair
 *
 * Description: Generates public and private key.
 *
 * Arguments:   - uint8_t *pk: pointer to output public key (allocated
 *                             array of XMSS_CRYPTO_PUBLICKEYBYTES bytes)
 *              - uint8_t *sk: pointer to output private key (allocated
 *                             array of XMSS_CRYPTO_SECRETKEYBYTES bytes)
 *
 * Returns 0 (success), -1 otherwise
 **************************************************/
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

/*************************************************
 * Name:        crypto_sign
 *
 * Description: Computes signature.
 *
 * Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
 *              - size_t *siglen: pointer to output length of signature
 *              - uint8_t *m:     pointer to message to be signed
 *              - size_t mlen:    length of message
 *              - uint8_t *sk:    pointer to bit-packed secret key
 *
 * Returns 0 (success), -1 otherwise
 **************************************************/
int crypto_sign(unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen, unsigned char *sk);

/*************************************************
 * Name:        crypto_sign_open
 *
 * Description: Verify signed message.
 *
 * Arguments:   - uint8_t *m: pointer to output message (allocated
 *                            array with smlen bytes), can be equal to sm
 *              - size_t *mlen: pointer to output length of message
 *              - const uint8_t *sm: pointer to signed message
 *              - size_t smlen: length of signed message
 *              - const uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signed message could be verified correctly and -1 otherwise
 **************************************************/
int crypto_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen, const unsigned char *pk);

/*************************************************
 * Name:        crypto_remain_signatures
 *
 * Description: Return number of signature left
 *
 * Arguments:   - size_t *remain: remaining signatures
 *              - size_t *max: maximum number of possibile signature
 *              - const uint8_t *sk: pointer to bit-packed private key
 *
 * Returns 0 (sucess), -1 otherwise
 **************************************************/
int crypto_remain_signatures(unsigned long long *remain,
                             unsigned long long *max, const unsigned char *sk);

#endif 

