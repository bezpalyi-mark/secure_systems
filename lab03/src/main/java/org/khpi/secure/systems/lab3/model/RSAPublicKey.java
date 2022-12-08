package org.khpi.secure.systems.lab3.model;

import java.math.BigInteger;

public class RSAPublicKey {
    private BigInteger n;

    private BigInteger e;

    public RSAPublicKey() {
        // needed for controller
    }

    public RSAPublicKey(BigInteger n, BigInteger e) {
        this.n = n;
        this.e = e;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getE() {
        return e;
    }
}
