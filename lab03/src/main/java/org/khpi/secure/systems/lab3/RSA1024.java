package org.khpi.secure.systems.lab3;

import org.khpi.secure.systems.lab3.model.RSAKeyPair;
import org.khpi.secure.systems.lab3.model.RSAPrivateKey;
import org.khpi.secure.systems.lab3.model.RSAPublicKey;

import java.math.BigInteger;
import java.util.Random;

public class RSA1024 {

    public static final BigInteger PUBLIC_EXPONENT = BigInteger.valueOf(65537);

    private RSA1024() {
    }

    public static RSAKeyPair generateRSAKeys() {
        int lp = (1024 + 1) >> 1;
        int lq = 1024 - lp;

        BigInteger n;
        BigInteger phi;

        do {
            BigInteger p = BigInteger.probablePrime(lp, new Random());
            BigInteger q = BigInteger.probablePrime(lq, new Random());

            n = p.multiply(q);

            BigInteger xMinusOne = p.subtract(BigInteger.ONE);
            BigInteger yMinusOne = q.subtract(BigInteger.ONE);

            phi = xMinusOne.multiply(yMinusOne);

        } while (!PUBLIC_EXPONENT.gcd(phi).equals(BigInteger.ONE));

        BigInteger d = PUBLIC_EXPONENT.modInverse(phi);

        RSAPublicKey rsaPublicKey = new RSAPublicKey(n, PUBLIC_EXPONENT);
        RSAPrivateKey rsaPrivateKey = new RSAPrivateKey(n, d);

        return new RSAKeyPair(rsaPublicKey, rsaPrivateKey);
    }

    public static byte[] encrypt(RSAPublicKey publicKey, byte[] msg) {

        if (msg.length > 128) {
            throw new IllegalArgumentException("Message length cannot be more than 128");
        }

        BigInteger integerMessage = new BigInteger(1, msg);
        BigInteger encrypted = integerMessage.modPow(publicKey.getE(), publicKey.getN());
        return encrypted.toByteArray();
    }

    public static byte[] decrypt(RSAPrivateKey privateKey, byte[] ciphered) {
        BigInteger msg = new BigInteger(1, ciphered);
        BigInteger decrypted = msg.modPow(privateKey.getD(), privateKey.getN());
        return decrypted.toByteArray();
    }
}
