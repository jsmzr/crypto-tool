package com.github.jsmzr.cryptotool.constants

enum class MacType(value: String) {
    HMAC_SHA512_256("HmacSHA512/256"),
    HMAC_SHA512_224("HmacSHA512/224"),
    HMAC_SHA512("HmacSHA512"),
    HMAC_SHA384("HmacSHA384"),
    HMAC_SHA256("HmacSHA256"),
    HMAC_SHA224("HmacSHA224"),
    HMAC_SHA1("HmacSHA1"),
    HMAC_MD5("HmacMD5");

    private val value: String

    init {
        this.value = value
    }

    fun getValue(): String {
        return value
    }
}