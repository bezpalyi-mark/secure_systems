package org.khpi.safe.systems.lab3.app.security;

import org.khpi.secure.systems.lab1.Hashes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Optional;
import java.util.stream.Stream;

public class FileCredentialsManager {

    @Value("classpath:credentials.txt")
    private Resource resourceFile;

    public boolean verifyCredentials(String username, String password) throws IOException {
        String userInput = String.format("%s:%s", Hashes.sha256(username), Hashes.sha256(password));

        try (Stream<String> credentials = Files.lines(Paths.get(resourceFile.getURI()))) {
            Optional<String> foundCredentials = credentials
                    .filter(creds -> creds.equals(userInput))
                    .findFirst();

            return foundCredentials.isPresent();
        }
    }
}
