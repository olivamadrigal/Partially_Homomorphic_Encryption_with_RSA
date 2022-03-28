/*
Partially Homomorphic Encryption with RSA

Simulation of Numerical Example from Massimo Bertaccini's Cryptography Algorithms from 2022.

Concept: computing on encrypted data such that we can verify the unencrypted result.

Scheme:

ENCRYPT ====> OPERATION ON ENCRYPTED DATA ====> ENCRYPTED RESULT ===> DECRYPT RESULT.

homomorphic encryption allows us to operate in the blind..
*/

#include "phe.h"

/*
RSA has homomorphic properties with respect to multiplication

*/
void PHE_RSA(void)
{
    BIGNUM *m1, *m2, *e, *d, *n, *c1, *c2, *c3, *c3p, *temp, *pt1, *pt2;
    BN_CTX *ctx;
    
    m1 = BN_new();
    m2 = BN_new();
    e = BN_new();
    d = BN_new();
    n = BN_new();
    c1 = BN_new();
    c2 = BN_new();
    c3 = BN_new();
    c3p = BN_new();
    temp = BN_new();
    pt1 = BN_new();
    pt2 = BN_new();
    ctx = BN_CTX_new();
    
    //set values as in page 302
    BN_set_word(m1, 11);
    BN_set_word(m2, 8);
    BN_set_word(e, 7);
    BN_set_word(d, 55);
    BN_set_word(n, 221); //n=p*q = 13*17
    
    //encrypt m1, m2
    BN_mod_exp(c1, m1, e, n, ctx);
    BN_mod_exp(c2, m2, e, n, ctx);
    
    //1st level: homomorphism of multiplication:
    BN_mod_mul(c3, c1, c2, n, ctx);
    printf("c1 = %s\t c2 = %s\t  c3 = %s\t\n", BN_bn2dec(c1), BN_bn2dec(c2), BN_bn2dec(c3));
   //2nd level correspondence:
    BN_mul(temp, m1, m2, ctx);
    BN_mod_exp(c3p, temp, e, n, ctx);
    
    if(BN_cmp(c3p, c3) == 0){printf("(m1*m2)^e MOD n == c1*c2 MOD n\n");}
   
    //Another importance correspondence: decryption of c3
    BN_mod_exp(pt1, c3, d, n, ctx); //decrypt multplication of ciphertexts
    BN_mod_mul(pt2, m1, m2, n, ctx); //multiplication on plaintext messages
    
    printf("c3^d = %s\t  m1*m2 = %s\t\n", BN_bn2dec(pt1), BN_bn2dec(pt2));

    if(BN_cmp(pt1, pt2) == 0){printf("(m1*m2)^e MOD n == c1*c2 MOD n\n");} //this is exactly what we wanted :)
    
    BN_free(m1);
    BN_free(m2);
    BN_free(e);
    BN_free(d);
    BN_free(n);
    BN_free(c1);
    BN_free(c2);
    BN_free(c3);
    BN_free(c3p);
    BN_free(pt1);
    BN_free(pt2);
    BN_free(temp);
}



