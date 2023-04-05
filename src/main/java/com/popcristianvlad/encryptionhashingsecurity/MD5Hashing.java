package com.popcristianvlad.encryptionhashingsecurity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5Hashing {

    private MD5Hashing() {
    }

    public static byte[] md5Hashing(String valueToHash) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(valueToHash.getBytes(StandardCharsets.UTF_8));
    }
}
