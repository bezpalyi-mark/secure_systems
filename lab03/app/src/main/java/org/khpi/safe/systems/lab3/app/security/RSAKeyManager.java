package org.khpi.safe.systems.lab3.app.security;

import org.khpi.secure.systems.lab1.Hashes;
import org.khpi.secure.systems.lab3.RSA1024;
import org.khpi.secure.systems.lab3.model.RSAKeyPair;
import org.springframework.core.io.Resource;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class RSAKeyManager {

    private final Resource publicKeysFile;
    private final Resource privateKeysFile;

    private final Map<String, BigInteger> userToPublicPart = new HashMap<>();
    private final Map<String, BigInteger> userToPrivatePart = new HashMap<>();

    public RSAKeyManager(Resource publicKeysFile, Resource privateKeysFile) {
        readCredsFromFile(publicKeysFile, userToPublicPart);
        readCredsFromFile(privateKeysFile, userToPrivatePart);

        this.publicKeysFile = publicKeysFile;
        this.privateKeysFile = privateKeysFile;
    }

    private void readCredsFromFile(Resource resource, Map<String, BigInteger> creds) {
        try (Stream<String> credentials = Files.lines(Paths.get(resource.getURI()))) {
            credentials.forEach(line -> creds.put(line.split(":")[0], new BigInteger(line.split(":")[1])));
        } catch (IOException e) {
            System.err.println("File not found:" + resource.getFilename());
        }
    }

    /**
     * @param username of existing user
     * @return modulus of generated keys
     * @throws IOException internal exception indicating that files were not found
     */
    public BigInteger generateKeys(String username) throws IOException {

        RSAKeyPair rsaKeyPair = RSA1024.generateRSAKeys();
        userToPublicPart.put(Hashes.sha256(username), rsaKeyPair.getRsaPublicKey().getN());
        userToPrivatePart.put(Hashes.sha256(username), rsaKeyPair.getRsaPrivateKey().getD());

        updateFile(publicKeysFile, userToPublicPart);
        updateFile(privateKeysFile, userToPrivatePart);

        return rsaKeyPair.getRsaPublicKey().getN();
    }

    private void updateFile(Resource resource, Map<String, BigInteger> userToKey) throws IOException {
        try (FileWriter fw = new FileWriter(resource.getFile(), false)) {

            for (Map.Entry<String, BigInteger> entry : userToKey.entrySet()) {
                String user = entry.getKey();
                BigInteger key = entry.getValue();

                fw.write(user + ":" + key);
            }
        }
    }

    /**
     * @param username of existing user
     * @return modulus of existing keys
     * @throws IOException internal exception indicating that file with public key part were not found
     */
    public BigInteger getN(String username) throws IOException {

        return getKey(publicKeysFile, username);
    }

    /**
     * @param username of existing user
     * @return private exponent of existing keys
     * @throws IOException internal exception indicating that file with private key part were not found
     */
    public BigInteger getD(String username) throws IOException {
        return getKey(privateKeysFile, username);
    }

    private BigInteger getKey(Resource resource, String username) throws IOException {
        try (Stream<String> credentials = Files.lines(Paths.get(resource.getURI()))) {
            Map<String, String> usernameToKey = credentials
                    .collect(Collectors.toMap(line -> line.split(":")[0], line -> line.split(":")[1]));

            String key = usernameToKey.get(Hashes.sha256(username));

            return key == null
                    ? null
                    : new BigInteger(key);
        }
    }
}
