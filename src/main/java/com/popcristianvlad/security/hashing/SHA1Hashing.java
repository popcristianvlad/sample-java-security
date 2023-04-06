package com.popcristianvlad.security.hashing;

import java.security.NoSuchAlgorithmException;

public class SHA1Hashing extends BaseHashing {

    public static byte[] sha1Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-1", valueToHash);
    }
}
