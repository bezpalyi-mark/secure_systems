package org.khpi.safe.systems.lab3.app.model;

import java.math.BigInteger;

public class PrivateKeyRequest {
    private BigInteger n;
    private BigInteger d;

    public PrivateKeyRequest() {
        // for controller
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getD() {
        return d;
    }
}
