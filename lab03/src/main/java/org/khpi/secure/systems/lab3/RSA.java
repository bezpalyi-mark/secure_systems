package org.khpi.secure.systems.lab3;

import org.khpi.secure.systems.lab3.model.RSAKeyPair;
import org.khpi.secure.systems.lab3.model.RSAPrivateKey;
import org.khpi.secure.systems.lab3.model.RSAPublicKey;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class RSA {

    private RSA() {
    }

    public static RSAKeyPair generateKeys(int q, int p) {
        long n = (long) q * p;

        int phi = (q - 1) * (p - 1);

        int e = findCoPrime(phi);
        int d = -1;

        for (int k = 0; d < 0; k++) {
            int remainder = (1 + k * phi) % e;

            if (remainder == 0) {
                d = (1 + k * phi) / e;
            }
        }

        RSAPublicKey rsaPublicKey = new RSAPublicKey(BigInteger.valueOf(n), BigInteger.valueOf(e));
        RSAPrivateKey rsaPrivateKey = new RSAPrivateKey(BigInteger.valueOf(n), BigInteger.valueOf(d));

        return new RSAKeyPair(rsaPublicKey, rsaPrivateKey);
    }

    public static byte[] encrypt(RSAPublicKey rsaPublicKey, byte[] input) {
        BigInteger message = new BigInteger(input);

        BigInteger result = message.pow(rsaPublicKey.getE().intValue()).mod(rsaPublicKey.getN());

        return result.toByteArray();
    }

    public static byte[] decrypt(RSAPrivateKey privateKey, byte[] encrypted) {
        BigInteger encryptedMessage = new BigInteger(encrypted);

        BigInteger result = encryptedMessage.pow(privateKey.getD().intValue()).mod(privateKey.getN());

        return result.toByteArray();
    }

    private static int findCoPrime(int phi) {
        List<Integer> sieveOfAtkinPrimes = findSieveOfAtkinPrimes(phi);

        for (Integer prime : sieveOfAtkinPrimes) {
            if (gcdEuclidean(prime, phi) == 1) {
                return prime;
            }
        }

        throw new IllegalStateException("No one co-prime is found for number: " + phi);
    }

    private static int gcdEuclidean(int a, int b) {
        int remainder = a % b;

        while (remainder > 0) {
            a = b;
            b = remainder;
            remainder = a % b;
        }

        return b;
    }

    private static List<Integer> findSieveOfAtkinPrimes(int limit) {
        boolean[] sieve = new boolean[limit];
        List<Integer> range = IntStream.range(0, limit)
                .boxed()
                .collect(Collectors.toList());

        for (int x = 1; x * x < limit; x++) {

            for (int y = 1; y * y < limit; y++) {

                int n = (4 * x * x) + (y * y);
                if (n <= limit && (n % 12 == 1 || n % 12 == 5)) {
                    sieve[n] ^= true;
                }

                n = (3 * x * x) + (y * y);
                if (n <= limit && n % 12 == 7) {
                    sieve[n] ^= true;
                }

                n = (3 * x * x) - (y * y);
                if (x > y && n <= limit && n % 12 == 11) {
                    sieve[n] ^= true;
                }

            }

        }

        for (int r = 5; r * r <= limit; r++) {
            if (sieve[r]) {
                for (int i = r * r; i <= limit; i += r * r)
                    sieve[i] = false;
            }
        }

        List<Integer> result = new ArrayList<>();
        result.add(2);
        result.add(3);

        for (int i = 0; i < range.size(); i++) {
            if (sieve[i]) {
                result.add(range.get(i));
            }
        }

        return result;
    }
}
