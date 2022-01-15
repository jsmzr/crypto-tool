package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.tink.ByteArrayReader
import com.google.crypto.tink.Aead
import com.google.crypto.tink.CleartextKeysetHandle

/**
 * Authenticated Encryption with Associated Data
 */
object TinkAeadUtil {
    @JvmStatic
    fun encrypt(plaintext: ByteArray, associatedData: ByteArray, key: ByteArray): ByteArray {
        val keySetHandle = CleartextKeysetHandle.read(ByteArrayReader(key))
        val aead = keySetHandle.getPrimitive(Aead::class.java)
        return aead.encrypt(plaintext, associatedData)
    }

    @JvmStatic
    fun decrypt(plaintext: ByteArray, associatedData: ByteArray, key: ByteArray): ByteArray {
        val keySetHandle = CleartextKeysetHandle.read(ByteArrayReader(key))
        val aead = keySetHandle.getPrimitive(Aead::class.java)
        return aead.decrypt(plaintext, associatedData)
    }
}