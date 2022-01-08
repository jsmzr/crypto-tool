package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.model.SignatureInfo
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

object SignatureUtil {
    @JvmStatic
    fun sign(info: SignatureInfo, key: ByteArray, data: ByteArray): ByteArray {
        val signer = Signature.getInstance(info.name)
        val keyFactory = KeyFactory.getInstance(info.key)
        signer.initSign(keyFactory.generatePrivate(PKCS8EncodedKeySpec(key)))
        signer.update(data)
        return signer.sign()
    }

    @JvmStatic
    fun verify(info: SignatureInfo, key: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        val signer = Signature.getInstance(info.name)
        val keyFactory = KeyFactory.getInstance(info.key)
        signer.initVerify(keyFactory.generatePublic(X509EncodedKeySpec(key)))
        signer.update(data)
        return signer.verify(signature)
    }
}