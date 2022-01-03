package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.constants.SymmetricType
import com.github.jsmzr.cryptotool.model.SymmetricInfo
import org.junit.Test
import javax.crypto.KeyGenerator
import kotlin.test.assertFails

class SymmetricUtilTest {
    @Test
    fun aesTest() {
        val data = "abcd12345678abcd".encodeToByteArray()
        val keyGenerator = KeyGenerator.getInstance("AES")
        // 16 bytes
        val iv = "test12345678test".encodeToByteArray()
        // 16, 24, 32 bytes
        keyGenerator.init(256)
        val key = keyGenerator.generateKey().encoded
        println(EncodeUtil.bytesToHexString(key))
        for (value in SymmetricType.values()) {
            if (!value.getValue().startsWith("AES/")) {
                continue
            }
            val info = SymmetricInfo(value.getValue())
            when (info.mode) {
                "ECB" -> {
                    symmetricTest(info, key, data)
                }
                "GCM" -> {
                    symmetricTest(info, key, data, iv, 128)
                }
                else -> {
                    symmetricTest(info, key, data, iv)
                }
            }
        }
    }

    @Test
    fun desTest() {
        val data = "abcd12345678abcd".encodeToByteArray()
        val keyGenerator = KeyGenerator.getInstance("DES")
        // 8 bytes
        val iv = "test1234".encodeToByteArray()
        // 7 bytes
        keyGenerator.init(56)
        val key = keyGenerator.generateKey().encoded
        for (value in SymmetricType.values()) {
            if (!value.getValue().startsWith("DES/")) {
                continue
            }
            val info = SymmetricInfo(value.getValue())
            if (info.mode == "ECB") {
                symmetricTest(info, key, data)
            } else {
                symmetricTest(info, key, data, iv)
            }
        }
    }

    @Test
    fun desedeTest() {
        val data = "abcd12345678abcd".encodeToByteArray()
        val keyGenerator = KeyGenerator.getInstance("DESede")
        // 8 bytes
        val iv = "test1234".encodeToByteArray()
        // 7 * 2 or 7 * 3 bytes (use 2 or 3 key encrypt with des)
        keyGenerator.init(112)
        val key = keyGenerator.generateKey().encoded
        for (value in SymmetricType.values()) {
            if (!value.getValue().startsWith("DESede/")) {
                continue
            }
            val info = SymmetricInfo(value.getValue())
            if (info.mode == "ECB") {
                symmetricTest(info, key, data)
            } else {
                symmetricTest(info, key, data, iv)
            }
        }
    }

    @Test
    fun noPaddingTest() {
        val data = "12345678".encodeToByteArray()
        val keyGenerator = KeyGenerator.getInstance("AES")
        // 16, 24, 32 bytes
        keyGenerator.init(256)
        val key = keyGenerator.generateKey().encoded
        assertFails { symmetricTest(SymmetricInfo("AES/ECB/NoPadding"), key, data) }
    }

    private fun symmetricTest(info: SymmetricInfo, key: ByteArray, data: ByteArray, iv: ByteArray? = null, tLen: Int = 96) {
        println(info)
        val encrypted = SymmetricUtil.encrypt(info, key, data, iv, tLen)
        val decrypted = SymmetricUtil.decrypt(info, key, encrypted, iv, tLen)
        assert(data.contentEquals(decrypted))
    }

}