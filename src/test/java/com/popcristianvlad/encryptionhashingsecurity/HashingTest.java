package com.popcristianvlad.encryptionhashingsecurity;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HashingTest {

    private static Stream<Arguments> md5HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "6b0676d647adc98a08a35c876d6fa809", 16),
                Arguments.arguments("AbcdAbcd12", "38fe3bb5cca175a02ae4d91e45058a25", 16),
                Arguments.arguments("AbcdAbcd1123", "8fba8ab793154520d4d15e931c3ec82e", 16),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "2b58e0cb6526990c78105e77889fca8c", 16)
        );
    }

    private static Stream<Arguments> sha1HashingTestValues() {
        return Stream.of(
                Arguments.arguments("AbcdAbcd11", "7a700dd88afb59d050f7aeb103870e1bedc2f370", 20),
                Arguments.arguments("AbcdAbcd12", "acda56d09baa35daf84362c60521b89c824cedf8", 20),
                Arguments.arguments("AbcdAbcd1123", "fdc425a854ae92feb5e7c4ad9478eb13e750af88", 20),
                Arguments.arguments("AbcdAbcdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafdffffffffffffffffffd1123", "c4435cf1fcfcde781a2472c8a9aaea8bcbf43dcc", 20)
        );
    }

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
    @DisplayName("Test MD5 hashing")
    @MethodSource("md5HashingTestValues")
    void testMD5Hashing(String valueToHash, String hexHashedValue, int byteOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.md5Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(byteOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-1 hashing")
    @MethodSource("sha1HashingTestValues")
    void testSHA1Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.sha1Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-224 hashing")
    @MethodSource("sha224HashingTestValues")
    void testSHA224Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.sha224Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-256 hashing")
    @MethodSource("sha256HashingTestValues")
    void testSHA256Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.sha256Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-384 hashing")
    @MethodSource("sha384HashingTestValues")
    void testSHA384Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.sha384Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-512 hashing")
    @MethodSource("sha512HashingTestValues")
    void testSHA512Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.sha512Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-512/224 hashing")
    @MethodSource("sha512224HashingTestValues")
    void testSHA512224Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.sha512224Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA-512/256 hashing")
    @MethodSource("sha512256HashingTestValues")
    void testSHA512256Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.sha512256Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA3-224 hashing")
    @MethodSource("sha3224HashingTestValues")
    void testSHA3224Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.sha3224Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA3-256 hashing")
    @MethodSource("sha3256HashingTestValues")
    void testSHA3256Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.sha3256Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA3-384 hashing")
    @MethodSource("sha3384HashingTestValues")
    void testSHA3384Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.sha3384Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }

    @ParameterizedTest
    @DisplayName("Test SHA3-512 hashing")
    @MethodSource("sha3512HashingTestValues")
    void testSHA3512Hashing(String valueToHash, String hexHashedValue, int bytesOutputSize) throws NoSuchAlgorithmException {
        byte[] hashedValue = Hashing.sha3512Hashing(valueToHash);
        assertEquals(hexHashedValue, new String(Hex.encodeHex(hashedValue)));
        assertEquals(bytesOutputSize, hashedValue.length);
    }
}
