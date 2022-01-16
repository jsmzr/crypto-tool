package com.github.jsmzr.cryptotool.constants

enum class SymmetricType(value: String) {
    // AES
    AES_ECB_NOPADDING("AES/ECB/NoPadding"),
    AES_CBC_NOPADDING("AES/CBC/NoPadding"),
    AES_CFB_NOPADDING("AES/CFB/NoPadding"),
    AES_OFB_NOPADDING("AES/OFB/NoPadding"),
    AES_CTR_NOPADDING("AES/CTR/NoPadding"),
    AES_GCM_NOPADDING("AES/GCM/NoPadding"),
    AES_ECB_PKCS5PADDING("AES/ECB/PKCS5Padding"),
    AES_CBC_PKCS5PADDING("AES/CBC/PKCS5Padding"),
    AES_CFB_PKCS5PADDING("AES/CFB/PKCS5Padding"),
    AES_OFB_PKCS5PADDING("AES/OFB/PKCS5Padding"),
    AES_CTR_PKCS5PADDING("AES/CTR/PKCS5Padding"),
    AES_GCM_PKCS5PADDING("AES/GCM/PKCS5Padding"),
    // DES
    DES_CBC_NOPADDING("DES/CBC/NoPadding"),
    DES_ECB_NOPADDING("DES/ECB/NoPadding"),
    DES_CFB_NOPADDING("DES/CFB/NoPadding"),
    DES_OFB_NOPADDING("DES/OFB/NoPadding"),
    DES_CTR_NOPADDING("DES/CTR/NoPadding"),
    DES_CBC_PKCS5PADDING("DES/CBC/PKCS5Padding"),
    DES_ECB_PKCS5PADDING("DES/ECB/PKCS5Padding"),
    DES_CFB_PKCS5PADDING("DES/CFB/PKCS5Padding"),
    DES_OFB_PKCS5PADDING("DES/OFB/PKCS5Padding"),
    DES_CTR_PKCS5PADDING("DES/CTR/PKCS5Padding"),
    // 3DES
    DESEDE_CBC_NOPADDING("DESede/CBC/NoPadding"),
    DESEDE_ECB_NOPADDING("DESede/ECB/NoPadding"),
    DESEDE_CFB_NOPADDING("DESede/CFB/NoPadding"),
    DESEDE_OFB_NOPADDING("DESede/OFB/NoPadding"),
    DESEDE_CTR_NOPADDING("DESede/CTR/NoPadding"),
    DESEDE_CBC_PKCS5PADDING("DESede/CBC/PKCS5Padding"),
    DESEDE_ECB_PKCS5PADDING("DESede/ECB/PKCS5Padding"),
    DESEDE_CFB_PKCS5PADDING("DESede/CFB/PKCS5Padding"),
    DESEDE_OFB_PKCS5PADDING("DESede/OFB/PKCS5Padding"),
    DESEDE_CTR_PKCS5PADDING("DESede/CTR/PKCS5Padding");

    private val value: String;

    init {
        this.value = value
    }
    fun getValue(): String {
        return this.value
    }
}