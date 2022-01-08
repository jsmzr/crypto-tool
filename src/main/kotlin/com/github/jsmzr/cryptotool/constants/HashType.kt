package com.github.jsmzr.cryptotool.constants

enum class HashType(value: String) {
    SHA3_224("SHA3-224"), SHA3_256("SHA3-256"), SHA3_384("SHA3-384"), SHA3_512("SHA3-512"),
    SHA224("SHA-224"),SHA256("SHA-256"), SHA384("SHA-384"), SHA512("SHA-512"),
    SHA512_224("SHA-512/224"), SHA512_256("SHA-512/256"),
    RipeMD128("RipeMD-128"), RipeMD160("RipeMD-160"), RipeMD256("RipeMD-256"), RipeMD320("RipeMD-320"),
    MD5("MD5"), MD2("MD2"),
    SHA1("SHA-1");
    private val value: String

    init {
        this.value = value
    }
    fun getValue(): String {
        return this.value
    }
}