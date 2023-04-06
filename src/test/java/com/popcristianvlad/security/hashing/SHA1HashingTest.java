package com.popcristianvlad.security.hashing;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SHA1HashingTest {

    private static Stream<Arguments> sha1HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "7a700dd88afb59d050f7aeb103870e1bedc2f370", 20),
                Arguments.arguments("AbcdAbcd12", "acda56d09baa35daf84362c60521b89c824cedf8", 20),
                Arguments.arguments("AbcdAbcd1123", "fdc425a854ae92feb5e7c4ad9478eb13e750af88", 20),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "c4435cf1fcfcde781a2472c8a9aaea8bcbf43dcc", 20)
        );
    }

    @ParameterizedTest
    @DisplayName("Test SHA-1 hashing")
    @MethodSource("sha1HashingTestValues")
    void testSHA1Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = SHA1Hashing.sha1Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }
}
