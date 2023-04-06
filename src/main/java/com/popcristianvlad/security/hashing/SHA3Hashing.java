package com.popcristianvlad.security.hashing;

import java.security.NoSuchAlgorithmException;

public class SHA3Hashing extends BaseHashing {

    public static byte[] sha3x224Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA3-224", valueToHash);
    }

    public static byte[] sha3x256Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA3-256", valueToHash);
    }

    public static byte[] sha3x384Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA3-384", valueToHash);
    }

    public static byte[] sha3x512Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA3-512", valueToHash);
    }
}
