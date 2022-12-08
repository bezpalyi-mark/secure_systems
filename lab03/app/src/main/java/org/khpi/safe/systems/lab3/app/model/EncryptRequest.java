package org.khpi.safe.systems.lab3.app.model;

public class EncryptRequest {
    private PublicKeyRequest publicKey;
    private String message;

    public EncryptRequest() {
        // used for controller
    }

    public PublicKeyRequest getPublicKey() {
        return publicKey;
    }

    public String getMessage() {
        return message;
    }
}
