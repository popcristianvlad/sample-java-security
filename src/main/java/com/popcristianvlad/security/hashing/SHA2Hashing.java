package com.popcristianvlad.security.hashing;

import java.security.NoSuchAlgorithmException;

public class SHA2Hashing extends BaseHashing {

    public static byte[] sha224Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-224", valueToHash);
    }

    public static byte[] sha256Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-256", valueToHash);
    }

    public static byte[] sha384Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-384", valueToHash);
    }

    public static byte[] sha512Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-512", valueToHash);
    }

    public static byte[] sha512224Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-512/224", valueToHash);
    }

    public static byte[] sha512256Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA-512/256", valueToHash);
    }

}
