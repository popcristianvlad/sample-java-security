package com.popcristianvlad.security.hashing;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MD5HashingTest {

    private static Stream<Arguments> md5HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "6b0676d647adc98a08a35c876d6fa809", 16),
                Arguments.arguments("AbcdAbcd12", "38fe3bb5cca175a02ae4d91e45058a25", 16),
                Arguments.arguments("AbcdAbcd1123", "8fba8ab793154520d4d15e931c3ec82e", 16),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "2b58e0cb6526990c78105e77889fca8c", 16)
        );
    }

    @ParameterizedTest
    @DisplayName("Test MD5 hashing")
    @MethodSource("md5HashingTestValues")
    void testMD5Hashing(String valueToHash, String hexHashedValue, int byteOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = MD5Hashing.md5Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(byteOutputSize, hashedValue.length);
    }
}
