package com.popcristianvlad.security.hashing;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SHA3HashingTest {

    private static Stream<Arguments> sha3224HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "1e900ad4f6a9c60411791f9344e5112f9341a06a192999d0bea74d75", 28),
                Arguments.arguments("AbcdAbcd12", "ea31f9d10b8ed2b5912e4181a76ab799cec98babeee6827401a981d3", 28),
                Arguments.arguments("AbcdAbcd1123", "c7aaa1aa4217d9b8ffd4761233060efd12f4b41d800db725eacaffb7", 28),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "0869eb18b954137e62055d0a1d99339223956539cf3ae75b1a91daa3", 28)
        );
    }

    private static Stream<Arguments> sha3256HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "9966e42078bd4b9c62c7a0541f338882391f13752d96ed5b1f0d88fc9a9e3ec4", 32),
                Arguments.arguments("AbcdAbcd12", "a72f68352eb0b27709a7f2b8b74a45a4e54d839db1884f40f7b46b9bd26edd27", 32),
                Arguments.arguments("AbcdAbcd1123", "a94ddd668570703d98a9bc8e693c3c8762d4a6eaf97af8e858f86fdfdf271352", 32),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "c3d860b88088da11f581599e0f421c2a5bcbc12e0c2b2a32ded8e5d49740cd94", 32)
        );
    }

    private static Stream<Arguments> sha3384HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "4694e5108f0e7e31614279465a7a8fe462cf2fdbeb245dc27dc211c0afd88c7017aa50fd1814fbd55582c2ae1804663c", 48),
                Arguments.arguments("AbcdAbcd12", "35edb9aebab97f7a5c5d28489c02d3be612846e67e139b73586a1ae1944019818a121748cd3bcf70e908455884a42957", 48),
                Arguments.arguments("AbcdAbcd1123", "f7ef983aa871648086e0b2acbe4f46c6a22b214be42e1bde796448c4020ae2d78c9c73fd6a9c63700c0b762f6f0eb312", 48),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "0808e3f9f1711eaeaa9264c787684642c1cfbcc3bcada4a415849fcc4008e14fd4ec13feb026944732669114ef861127", 48)
        );
    }

    private static Stream<Arguments> sha3512HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "6fa2642a25aa29aa9519ddea2b1e624d5f17d01df7fcf9179801be21f8172a772d140dccdbe42fd4123912e19e0c343d4aacd963d02da2529dedb5a291691254", 64),
                Arguments.arguments("AbcdAbcd12", "441dfbf41cfb59fb971d7cca75d245352cc4d7c59ad12350f3bbcbf489646965147d86a5427aaeede32b1a6f8b741a68d0d58971b50a53f22146cda34c9607af", 64),
                Arguments.arguments("AbcdAbcd1123", "ea72327a9d1726ec896fa4772599cba4f5c82c67db86f7095beab32f236bb308cc45c0507084cab0ec8921ba0015be8923e4337dc8fa71ada5a209fc66643988", 64),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "85463fa28bf847ec1c7280e916a16d4b6590b991c39185e86794e5ae429c7d2fbd8f7e7f2f783364cbdd046e8d0fbf8bec3c8bb7c2b7ab6e5095d0d8aa8eabe7", 64)
        );
    }

    @ParameterizedTest
    @DisplayName("Test SHA3-224 hashing")
    @MethodSource("sha3224HashingTestValues")
    void testSHA3224Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = SHA3Hashing.sha3224Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA3-256 hashing")
    @MethodSource("sha3256HashingTestValues")
    void testSHA3256Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = SHA3Hashing.sha3256Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA3-384 hashing")
    @MethodSource("sha3384HashingTestValues")
    void testSHA3384Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = SHA3Hashing.sha3384Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA3-512 hashing")
    @MethodSource("sha3512HashingTestValues")
    void testSHA3512Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = SHA3Hashing.sha3512Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }
}
