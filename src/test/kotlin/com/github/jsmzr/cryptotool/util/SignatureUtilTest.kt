package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.constants.SignatureType
import com.github.jsmzr.cryptotool.model.SignatureInfo
import org.junit.Test

class SignatureUtilTest {
    val rsaKey = AsymmetricUtil.generateKey("RSA")

    // dsa key length 512 ~ 1024 && key.size % 64 == 0
    val dsaKey = AsymmetricUtil.generateKey("DSA")

    // ec key length 112~571
    val ecdsaKey = AsymmetricUtil.generateKey("EC", 571)

    @Test
    fun signatureTest() {
        for (value in SignatureType.values()) {
            commonCheck(SignatureInfo(value.getValue()))
        }
    }

    private fun commonCheck(info: SignatureInfo) {
        val data = "This is a data to be signature".encodeToByteArray()
        val key = when (info.key) {
            "RSA" -> {
                rsaKey
            }
            "DSA" -> {
                dsaKey
            }
            "EC" -> {
                ecdsaKey
            }
            else -> {
                null
            }
        }
        if (key == null || key.public == null || key.private == null) {
            return
        }
        val signed = SignatureUtil.sign(info, key.private.encoded, data)
        val verify = SignatureUtil.verify(info, key.public.encoded, data, signed)
        println("signature with [${info}] to [${EncodeUtil.bytesToHexString(signed)}], verify is [${verify}]")
        assert(verify)
    }
}