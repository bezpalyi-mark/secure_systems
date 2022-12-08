package org.khpi.secure.systems.lab3;

import org.junit.jupiter.api.Test;
import org.khpi.secure.systems.lab3.model.RSAKeyPair;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class RSA1024Test {

    @Test
    void testRSA1024Encryption() {
        String input = "When someone first begins to consider using encryption to protect business data, they " +
                "discover that there are two general types:"; //max length is 128 bytes or 1024 bits

        RSAKeyPair rsaKeyPair = RSA1024.generateRSAKeys();

        byte[] encryptedBytes = RSA1024.encrypt(rsaKeyPair.getRsaPublicKey(), input.getBytes());

        assertNotEquals(input, new String(encryptedBytes, StandardCharsets.UTF_8));

        byte[] decryptedBytes = RSA1024.decrypt(rsaKeyPair.getRsaPrivateKey(), encryptedBytes);

        assertEquals(input, new String(decryptedBytes, StandardCharsets.UTF_8));
    }
}