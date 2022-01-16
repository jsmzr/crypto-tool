package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.tink.ByteArrayReader
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.DeterministicAead

/**
 * Deterministic Authenticated Encryption with Associated Data
 */
object TinkDaeadUtil {

    @JvmStatic
    fun encrypt(plaintext: ByteArray, associatedData: ByteArray, key: ByteArray): ByteArray {
        val keySetHandle = CleartextKeysetHandle.read(ByteArrayReader(key))
        val daead = keySetHandle.getPrimitive(DeterministicAead::class.java)
        return daead.encryptDeterministically(plaintext, associatedData)
    }


    @JvmStatic
    fun decrypt(plaintext: ByteArray, associatedData: ByteArray, key: ByteArray): ByteArray {
        val keySetHandle = CleartextKeysetHandle.read(ByteArrayReader(key))
        val daead = keySetHandle.getPrimitive(DeterministicAead::class.java)
        return daead.decryptDeterministically(plaintext, associatedData)
    }
}