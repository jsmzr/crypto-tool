package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.tink.ByteArrayReader
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.Mac

/**
 * Message Authentication Codes
 */
object TinkMacUtil {
    @JvmStatic
    fun mac(data: ByteArray, key: ByteArray): ByteArray {
        val keySetHandle = CleartextKeysetHandle.read(ByteArrayReader(key))
        val mac = keySetHandle.getPrimitive(Mac::class.java)
        return mac.computeMac(data)
    }


    @JvmStatic
    fun verify(data: ByteArray, key: ByteArray, tag: ByteArray) {
        val keySetHandle = CleartextKeysetHandle.read(ByteArrayReader(key))
        val mac = keySetHandle.getPrimitive(Mac::class.java)
        mac.verifyMac(tag, data)
    }
}