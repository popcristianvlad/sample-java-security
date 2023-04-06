package com.popcristianvlad.security.hashing;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class BaseHashing {

    BaseHashing() {
    }

    static byte[] hash(String algorithm, String valueToHash) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(valueToHash.getBytes(StandardCharsets.UTF_8));
    }
}
