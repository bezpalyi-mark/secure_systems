package org.khpi.safe.systems.lab3.app;

import org.khpi.safe.systems.lab3.app.model.DecryptRequest;
import org.khpi.safe.systems.lab3.app.model.EncryptRequest;
import org.khpi.safe.systems.lab3.app.security.FileCredentialsManager;
import org.khpi.safe.systems.lab3.app.security.RSAKeyManager;
import org.khpi.secure.systems.lab3.RSA1024;
import org.khpi.secure.systems.lab3.model.RSAPrivateKey;
import org.khpi.secure.systems.lab3.model.RSAPublicKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

@RestController
public class EncryptionController {

    private FileCredentialsManager fileCredentialsManager;
    private RSAKeyManager keyManager;

    @PostMapping("/generateKeys")
    public ResponseEntity<RSAPublicKey> generateKeys(@RequestHeader("Username") String username,
                                                     @RequestHeader("Password") String password) throws IOException {

        if (fileCredentialsManager.verifyCredentials(username, password)) {
            BigInteger n = keyManager.generateKeys(username);

            RSAPublicKey rsaPublicKey = new RSAPublicKey(n, RSA1024.PUBLIC_EXPONENT);

            return new ResponseEntity<>(rsaPublicKey, HttpStatus.OK);
        }

        return new ResponseEntity<>(new RSAPublicKey(BigInteger.ZERO, BigInteger.ZERO), HttpStatus.UNAUTHORIZED);
    }

    @GetMapping("/key")
    public ResponseEntity<RSAPublicKey> getPublicKey(@RequestHeader("Username") String username,
                                                     @RequestHeader("Password") String password) throws IOException {

        if (fileCredentialsManager.verifyCredentials(username, password)) {

            BigInteger publicKey = keyManager.getN(username);
            return new ResponseEntity<>(new RSAPublicKey(publicKey, RSA1024.PUBLIC_EXPONENT), HttpStatus.OK);
        }

        return new ResponseEntity<>(new RSAPublicKey(BigInteger.ZERO, BigInteger.ZERO), HttpStatus.UNAUTHORIZED);
    }

    @PostMapping("/encrypt")
    public ResponseEntity<String> encrypt(@RequestBody EncryptRequest request) {
        if (request.getMessage().length() > 128) {
            return new ResponseEntity<>("Message length cannot be more than 128", HttpStatus.BAD_REQUEST);
        }

        RSAPublicKey rsaPublicKey = new RSAPublicKey(request.getPublicKey().getN(), request.getPublicKey().getE());

        byte[] encryptedBytes = RSA1024.encrypt(rsaPublicKey, request.getMessage().getBytes());

        BigInteger result = new BigInteger(1, encryptedBytes);
        return new ResponseEntity<>(result.toString(), HttpStatus.OK);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<String> decrypt(@RequestBody DecryptRequest request, @RequestHeader("Username") String username,
                                          @RequestHeader("Password") String password) throws IOException {

        if (fileCredentialsManager.verifyCredentials(username, password)) {
            BigInteger d = keyManager.getD(username);
            BigInteger n = keyManager.getN(username);

            RSAPrivateKey rsaPrivateKey = new RSAPrivateKey(n, d);

            byte[] decryptedBytes = RSA1024.decrypt(rsaPrivateKey, request.getEncryptedMessage().toByteArray());

            return new ResponseEntity<>(new String(decryptedBytes, StandardCharsets.UTF_8), HttpStatus.OK);
        }

        return new ResponseEntity<>("Unauthorized", HttpStatus.UNAUTHORIZED);
    }

    @Autowired
    public void setFileCredentialsManager(FileCredentialsManager fileCredentialsManager) {
        this.fileCredentialsManager = fileCredentialsManager;
    }

    @Autowired
    public void setKeyManager(RSAKeyManager keyManager) {
        this.keyManager = keyManager;
    }
}
