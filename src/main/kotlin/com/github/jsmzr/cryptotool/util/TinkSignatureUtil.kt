package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.tink.ByteArrayReader
import com.google.crypto.tink.*

object TinkSignatureUtil {
    @JvmStatic
    fun sign(data: ByteArray, key: ByteArray): ByteArray {
        val keySetHandle = CleartextKeysetHandle.read(ByteArrayReader(key))
        val signer = keySetHandle.getPrimitive(PublicKeySign::class.java)

        return signer.sign(data)
    }

    @JvmStatic
    fun verify(data: ByteArray, key: ByteArray, sign: ByteArray) {
        val keySetHandle = CleartextKeysetHandle.read(ByteArrayReader(key))
        val verifier = keySetHandle.getPrimitive(PublicKeyVerify::class.java)
        verifier.verify(sign, data)
    }
}