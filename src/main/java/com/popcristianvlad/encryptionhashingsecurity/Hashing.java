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

    public static byte[] sha3224Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA3-224", valueToHash);
    }

    public static byte[] sha3256Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA3-256", valueToHash);
    }

    public static byte[] sha3384Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA3-384", valueToHash);
    }

    public static byte[] sha3512Hashing(String valueToHash) throws NoSuchAlgorithmException {
        return hash("SHA3-512", valueToHash);
    }

    private static byte[] hash(String algorithm, String valueToHash) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        return md.digest(valueToHash.getBytes(StandardCharsets.UTF_8));
    }
}
