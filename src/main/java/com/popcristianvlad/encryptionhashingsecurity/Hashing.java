package com.popcristianvlad.encryptionhashingsecurity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hashing {

    private Hashing() {
    }

    public static byte[] md5Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("MD5", valueToHash);
    }

    public static byte[] sha1Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-1", valueToHash);
    }

    private static byte[] hash(String algorithm, String valueToHash) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(valueToHash.getBytes(StandardCharsets.UTF_8));
    }
}
