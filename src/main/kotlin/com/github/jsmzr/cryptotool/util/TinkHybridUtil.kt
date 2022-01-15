package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.tink.ByteArrayReader
import com.google.crypto.tink.*

object TinkHybridUtil {
    @JvmStatic
    fun encrypt(plaintext: ByteArray, context: ByteArray, key: ByteArray): ByteArray {
        val keySetHandle = CleartextKeysetHandle.read(ByteArrayReader(key))
        val hybridEncrypt = keySetHandle.getPrimitive(HybridEncrypt::class.java)
        return hybridEncrypt.encrypt(plaintext, context)
    }

    @JvmStatic
    fun decrypt(ciphertext: ByteArray, context: ByteArray, key: ByteArray): ByteArray {
        val keySetHandle = CleartextKeysetHandle.read(ByteArrayReader(key))
        val hybridDecrypt = keySetHandle.getPrimitive(HybridDecrypt::class.java)
        return hybridDecrypt.decrypt(ciphertext, context)
    }

}