package org.khpi.secure.systems.lab2;


import org.junit.jupiter.api.Test;
import org.khpi.secure.systems.utils.ByteUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

class Aes128Test {

    private static final String PLAIN_TEXT = "The back is a complex structure to understand, made up of muscles, " +
            "ligaments, bones, nerves, and discs.  With smart phones and computers being used more consistently i" +
            "n everyday life, it’s easy to put unwanted strain on these muscles and ligaments in our necks and sp" +
            "ines. Because overuse of this technology can lead to poor posture and a number of other injuries dow" +
            "n the line, it can be dangerous to a person’s overall health without the right attention.";

    private static final String PASSWORD = "Some strange pas";

    @Test
    void testAes128() throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        byte[] actualBytes = Aes128.encrypt(PLAIN_TEXT, PASSWORD);

        Key aesKey = new SecretKeySpec(PASSWORD.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] expectedBytes = cipher.doFinal(PLAIN_TEXT.getBytes());

        assertEquals(expectedBytes.length, actualBytes.length);

        for (int i = 0; i < expectedBytes.length; i++) {
            assertEquals(expectedBytes[i], actualBytes[i]);
        }
    }
}