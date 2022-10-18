package org.khpi.safe.systems.lab1;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class HashesTest {
    @Test
    void testSha256() throws URISyntaxException, IOException, NoSuchAlgorithmException {
        String proseFile = readProseFile();

        String actual = Hashes.sha256(proseFile);
        String expected = javaCoreHash(proseFile);

        assertEquals(expected, actual);
    }

    // Suggested by baeldung https://www.baeldung.com/sha-256-hashing-java
    private String javaCoreHash(String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(encodedhash);
    }

    private String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private String readProseFile() throws URISyntaxException, IOException {
        URL resource = HashesTest.class.getResource("/prose.txt");
        assertNotNull(resource);
        try (Stream<String> stream = Files.lines(Path.of(resource.toURI()))) {
            return stream.collect(Collectors.joining());
        }
    }
}