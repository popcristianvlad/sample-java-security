package com.popcristianvlad.security.hashing;

import java.security.NoSuchAlgorithmException;

public class SHA2Hashing extends BaseHashing {

    public static byte[] sha2x224Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-224", valueToHash);
    }

    public static byte[] sha2x256Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-256", valueToHash);
    }

    public static byte[] sha2x384Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-384", valueToHash);
    }

    public static byte[] sha2x512Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-512", valueToHash);
    }

    public static byte[] sha2x512x224Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-512/224", valueToHash);
    }

    public static byte[] sha2x512x256Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-512/256", valueToHash);
    }
}
