package com.github.jsmzr.cryptotool.constants

enum class SignatureType(value: String) {
    SHA512_256_WITH_RSA("SHA512/256withRSA"), SHA512_224_WITH_RSA("SHA512/224withRSA"), SHA512_WITH_RSA("SHA512withRSA"),
    SHA384_WITH_RSA("SHA384withRSA"), SHA256_WITH_RSA("SHA256withRSA"),
    SHA224_WITH_RSA("SHA224withRSA"), SHA1_WITH_RSA("SHA1withRSA"),
    MD5_WITH_RSA("MD5withRSA"), MD2_WITH_RSA("MD2withRSA"),
    SHA512_WITH_ECDSA("SHA512withECDSA"),
    SHA384_WITH_ECDSA("SHA384withECDSA"), SHA256_WITH_ECDSA("SHA256withECDSA"),
    SHA224_WITH_ECDSA("SHA224withECDSA"), SHA1_WITH_ECDSA("SHA1withECDSA"),
    SHA256_WITH_DSA("SHA256withDSA"), SHA224_WITH_DSA("SHA224withDSA"), SHA1_WITH_DSA("SHA1withDSA");

    private val value: String

    init {
        this.value = value
    }

    fun getValue(): String {
        return this.value
    }
}