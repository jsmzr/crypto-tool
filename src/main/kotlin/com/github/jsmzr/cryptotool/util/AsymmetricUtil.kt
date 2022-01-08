package com.github.jsmzr.cryptotool.util

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

object AsymmetricUtil {
    /**
     * asymmetric encrypt
     * @param alg RSA
     * @param pubKey Length is 512,1024,2048,4096, Key length minimum 512 largest 1024 * 64
     * @param data Clear text
     * @return Length is determined by the key and clear text
     */
    @JvmStatic
    fun encrypt(alg: String, pubKey: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(alg)
        val keyFactory = KeyFactory.getInstance(alg)
        cipher.init(Cipher.ENCRYPT_MODE, keyFactory.generatePublic(X509EncodedKeySpec(pubKey)))
        return cipher.doFinal(data)
    }


    @JvmStatic
    fun decrypt(alg: String, priKey: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(alg)
        val keyFactory = KeyFactory.getInstance(alg)
        cipher.init(Cipher.DECRYPT_MODE, keyFactory.generatePrivate(PKCS8EncodedKeySpec(priKey)))
        return cipher.doFinal(data)
    }

    /**
     * Generate key
     * RSA key length minimum 512 largest 1024 * 64
     *
     * EC key length minimum 112 largest 571
     *
     * DSA key length minimum 512 largest 1024 && length % 64 == 0
     */
    @JvmStatic
    fun generateKey(alg: String, size: Int = 1024): KeyPair {
        val generator = KeyPairGenerator.getInstance(alg)
        generator.initialize(size)
        return generator.genKeyPair()
    }
}