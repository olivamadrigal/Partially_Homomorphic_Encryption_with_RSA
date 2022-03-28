#ifndef phe_h
#define phe_h

/*

Partially Homomorphic Encryption with RSA

Simulation of Numerical Example from Massimo Bertaccini's Cryptography Algorithms from 2022.

Concept: computing on encrypted data such that we can verify the unencrypted result.

Scheme:

ENCRYPT ====> OPERATION ON ENCRYPTED DATA ====> ENCRYPTED RESULT ===> DECRYPT RESULT.

*/
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <assert.h>
#include <openssl/bn.h> //BN multiprecision strucuts
#include <openssl/rsa.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

/*
RSA has homomorphic properties with respect to multiplication
*/
void PHE_RSA(void);


#endif /* phe_h */
