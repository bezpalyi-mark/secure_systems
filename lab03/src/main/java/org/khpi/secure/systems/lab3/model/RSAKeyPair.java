package org.khpi.secure.systems.lab3.model;

public class RSAKeyPair {
    private final RSAPublicKey rsaPublicKey;
    private final RSAPrivateKey rsaPrivateKey;

    public RSAKeyPair(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey) {
        this.rsaPublicKey = rsaPublicKey;
        this.rsaPrivateKey = rsaPrivateKey;
    }

    public RSAPublicKey getRsaPublicKey() {
        return rsaPublicKey;
    }

    public RSAPrivateKey getRsaPrivateKey() {
        return rsaPrivateKey;
    }
}
