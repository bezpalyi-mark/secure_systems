package org.khpi.secure.systems.lab3.model;

import java.math.BigInteger;

public class RSAPrivateKey {
    private final BigInteger n;

    private final BigInteger d;

    public RSAPrivateKey(BigInteger n, BigInteger d) {
        this.n = n;
        this.d = d;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getD() {
        return d;
    }
}
