package com.github.jsmzr.cryptotool.util

import org.junit.Test
import java.util.stream.IntStream

class AsymmetricUtilTest {
    @Test
    fun asymmetricTest() {
        val alg = "RSA"
        val key = AsymmetricUtil.generateKey(alg, 512)
        val data = "This is the content that needs to be encrypted".encodeToByteArray()
        val encrypted = AsymmetricUtil.encrypt(alg, key.public.encoded, data)
        val decrypted = AsymmetricUtil.decrypt(alg, key.private.encoded, encrypted)
        assert(decrypted.contentEquals(data))
    }

    @Test
    fun generateKeyTest() {
        val rsaKeyLength = intArrayOf(1024, 2048)
        for (i in rsaKeyLength) {
            AsymmetricUtil.generateKey("RSA", i)
        }
        val ecKeyLength = intArrayOf(112, 128, 256, 512, 571)
        for (i in ecKeyLength) {
            AsymmetricUtil.generateKey("EC", i)
        }
        val dsaKeyLength = IntStream.range(512, 1025).filter { it % 64 == 0 }.toArray()
        for (i in dsaKeyLength) {
            println(i)
            AsymmetricUtil.generateKey("DSA", i)
        }
    }
}