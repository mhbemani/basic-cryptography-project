package asymmetric;

import java.math.BigInteger;

// RSA encrypte and decrypte    ...done
// RSA encode and decode        ...NOT YET
public class RSA {
    public BigInteger encryption(BigInteger plainText, BigInteger public_key, BigInteger modulo){
        return plainText.modPow(public_key, modulo);
    }

    public BigInteger decryption(BigInteger cipherText, BigInteger private_key, BigInteger modulo){
        return cipherText.modPow(private_key, modulo);
    }

    // public BigInteger encode(){

    // }

    // public BigInteger decode(){

    // }
}
