package com.popcristianvlad.security.hashing;

import java.security.NoSuchAlgorithmException;

public class MD5Hashing extends BaseHashing {

    public static byte[] md5Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("MD5", valueToHash);
    }
}
