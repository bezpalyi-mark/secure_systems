package org.khpi.safe.systems.lab3.app.model;

import java.math.BigInteger;

public class PublicKeyRequest {
    private BigInteger n;
    private BigInteger e;

    public PublicKeyRequest() {
        // for controller
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getE() {
        return e;
    }
}
