package com.github.jsmzr.cryptotool.util

import org.apache.commons.codec.binary.Hex
import java.util.*


object EncodeUtil {

    @JvmStatic
    fun base64ToBytes(data: String): ByteArray {
        return Base64.getDecoder().decode(data)
    }

    @JvmStatic
    fun bytesToBase64(bytes: ByteArray): String {
        return Base64.getEncoder().encodeToString(bytes)
    }

    @JvmStatic
    fun hexStringToBytes(data: String): ByteArray? {
        if (data.isEmpty()) {
            return null
        }
        if (data.startsWith("0x", true)) {
            return Hex.decodeHex(data.substring(2))
        }
        return Hex.decodeHex(data)
    }

    @JvmStatic
    fun bytesToHexString(bytes: ByteArray): String {
        return Hex.encodeHexString(bytes)
    }

}