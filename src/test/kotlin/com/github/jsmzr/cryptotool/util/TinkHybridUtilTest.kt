package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.constants.TinkHybridType
import com.github.jsmzr.cryptotool.tink.ByteArrayWriter
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.hybrid.HybridConfig
import org.junit.Test

class TinkHybridUtilTest {
    init {
        HybridConfig.register()
    }

    @Test
    fun allHybridTest() {
        val contextInfo = "context info".encodeToByteArray()
        val plainText = "This is hybrid for Google Tink".encodeToByteArray()
        for (value in TinkHybridType.values()) {
            hybridTest(value.name, plainText, contextInfo)
        }
    }
    private fun hybridTest(alg: String, plainText: ByteArray, contextInfo: ByteArray) {
        val keySetHandle = KeysetHandle.generateNew(KeyTemplates.get(alg))
        val priWriter = ByteArrayWriter()
        val pubWriter = ByteArrayWriter()
        CleartextKeysetHandle.write(keySetHandle, priWriter)
        CleartextKeysetHandle.write(keySetHandle.publicKeysetHandle, pubWriter)

        val encrypted = TinkHybridUtil.encrypt(plainText, contextInfo, pubWriter.byteArray)
        val decrypted = TinkHybridUtil.decrypt(encrypted, contextInfo, priWriter.byteArray)
        assert(plainText.contentEquals(decrypted))
    }
}