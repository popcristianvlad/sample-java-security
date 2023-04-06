package com.popcristianvlad.security.hashing;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SHA2HashingTest {

    private static Stream<Arguments> sha224HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "83f9854dcd51ee30c1208f4162cd1d278e32664dd1ab24e1d536f0b5", 28),
                Arguments.arguments("AbcdAbcd12", "562377f51427e5344d66a64ec49dd9a66c6a4ded5697839645e5e22f", 28),
                Arguments.arguments("AbcdAbcd1123", "feab01f58184884ee31ac02d75f5a006a4edc78623b4ad391b6ac7c1", 28),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "9468269dbc8d505aacd02ecc87c1f9c6f3e2310afeaa1119f528b2b5", 28)
        );
    }

    private static Stream<Arguments> sha256HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "2cbbe56f33b67080f2759c33bce435ef0dcffdb9c633f624077f897bbc608236", 32),
                Arguments.arguments("AbcdAbcd12", "bf8334c079d3012ad50badbb14d48de388078c8a9510e57fbe753f26346805bc", 32),
                Arguments.arguments("AbcdAbcd1123", "068f318809acab6a3d45d13e02682d7f18399b79dda0cad235a30e92a5c43f04", 32),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "8b548285ad7090fd11f2aa0104e101a685adc01e23936add0223f6318db5cca6", 32)
        );
    }

    private static Stream<Arguments> sha384HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "7229e97e8a640137d899176c5201d4a212404ea9f1a9ed4c329dc71ab52524053c11250e41074791efec5a16fa505131", 48),
                Arguments.arguments("AbcdAbcd12", "0ecf6124ae465e3c5c560ad60e7e4fba0996741b001d908a4df4ac9a11c7270548b5051aa7a861bd1cb94bf74b7e5f43", 48),
                Arguments.arguments("AbcdAbcd1123", "28d66007285af5ee60ab8d05ba1356ba68b3a63dea75af701ff9c978ee66d0c21fd3f405082dfbde1a3d023c95ef3958", 48),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "ed566d8da72c86104eca015c33e72781d6952a6803c10b735591d9988c65c239ca36c19d3df38de09adf101664dbb22d", 48)
        );
    }

    private static Stream<Arguments> sha512HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "10d7a0e812977d504e355a97cc18ad84b7e4c362dadb1f34bc9b46bd55b3984090fa577dbb7ced1f3eb27a2e97b960d92091e99d372f38337ef6cdb818864a2f", 64),
                Arguments.arguments("AbcdAbcd12", "5dead843bd5c06b06e99d11ffaeddbcbf7e214946f61424970b54f40411370095068f0a74da8804b5e63a5364c5e4146a2b885228965cb3e4159b02a4c099d5c", 64),
                Arguments.arguments("AbcdAbcd1123", "142b1458ab1046ea33deff69de484245e445158519ef6b00c730f0f1e0ce368a5c89a6a08ded5d32591d438488c85c4671419555b615f7d88807abc470430a19", 64),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "45bad6e4f9b085fdf7ef394024afed088a3c0d958d114550e44cdb2ea63253b2fef9d6399ff0490a6d64da593955ba294da03bae1c59999b49589e020f014eb9", 64)
        );
    }

    private static Stream<Arguments> sha512224HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "12da9e0c06af84ab9ce73bd78925970864090ae1b2201a9f5ffea42a", 28),
                Arguments.arguments("AbcdAbcd12", "4459e3ddfb15a512671895fe4b41d1f468815a71613db29c1e179bbc", 28),
                Arguments.arguments("AbcdAbcd1123", "c378b0101f189a5500b932bb3f45ae483955389ed3fbb68ae969b9a8", 28),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "fcc4dc21f32219f9a984d123c22096c8d66f94ca621a123eb73aca6e", 28)
        );
    }

    private static Stream<Arguments> sha512256HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "bd3e4ea88aa34f686edb1a0929c23bce901f3418b882782b236ebb2fd1cf303c", 32),
                Arguments.arguments("AbcdAbcd12", "f2fc7bf36e8de89b7818acdbc5340dbf9a2e41e5a28ec13bfb3cde9cc3a4e0ea", 32),
                Arguments.arguments("AbcdAbcd1123", "e39d87d8e44d48432ec95ebdb8f6ab1a0ee7ded936505e885a1191a142246643", 32),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "b4f28d2285ba6cf30d45e57495e822173373fd077a71e2d0155d08de33bb3e9b", 32)
        );
    }

    @ParameterizedTest
    @DisplayName("Test SHA-224 hashing")
    @MethodSource("sha224HashingTestValues")
    void testSHA224Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = SHA2Hashing.sha224Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-256 hashing")
    @MethodSource("sha256HashingTestValues")
    void testSHA256Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = SHA2Hashing.sha256Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-384 hashing")
    @MethodSource("sha384HashingTestValues")
    void testSHA384Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = SHA2Hashing.sha384Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-512 hashing")
    @MethodSource("sha512HashingTestValues")
    void testSHA512Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = SHA2Hashing.sha512Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-512/224 hashing")
    @MethodSource("sha512224HashingTestValues")
    void testSHA512224Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = SHA2Hashing.sha512224Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-512/256 hashing")
    @MethodSource("sha512256HashingTestValues")
    void testSHA512256Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = SHA2Hashing.sha512256Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }
}
