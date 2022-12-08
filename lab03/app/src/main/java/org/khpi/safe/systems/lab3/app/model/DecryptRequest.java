package org.khpi.safe.systems.lab3.app.model;

import java.math.BigInteger;

public class DecryptRequest {
    private BigInteger encryptedMessage;

    public DecryptRequest() {
        // used for controller
    }

    public BigInteger getEncryptedMessage() {
        return encryptedMessage;
    }
}
