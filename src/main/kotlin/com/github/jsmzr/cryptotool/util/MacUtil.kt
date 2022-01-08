package com.github.jsmzr.cryptotool.util

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object MacUtil {
    @JvmStatic
    fun mac(alg: String, key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(alg)
        mac.init(SecretKeySpec(key, ""))
        return mac.doFinal(data)
    }

}