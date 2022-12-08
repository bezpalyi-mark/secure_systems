package org.khpi.secure.systems.lab3;

import org.junit.jupiter.api.Test;
import org.khpi.secure.systems.lab3.model.RSAKeyPair;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class RSATest {

    @Test
    void testRSAEncryption() {
        String input = "123";

        RSAKeyPair rsaKeyPair = RSA.generateKeys(3119, 1109); //max 3 bytes for q=3119 and p=1109
        byte[] encryptedBytes = RSA.encrypt(rsaKeyPair.getRsaPublicKey(), input.getBytes());

        assertNotEquals(input, new String(encryptedBytes, StandardCharsets.UTF_8));

        byte[] decryptedBytes = RSA.decrypt(rsaKeyPair.getRsaPrivateKey(), encryptedBytes);

        assertEquals(input, new String(decryptedBytes, StandardCharsets.UTF_8));
    }
}