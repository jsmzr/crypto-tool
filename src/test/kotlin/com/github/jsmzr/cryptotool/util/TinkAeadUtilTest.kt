package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.constants.TinkAeadType
import com.github.jsmzr.cryptotool.tink.ByteArrayWriter
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.aead.AeadConfig
import org.junit.Test

class TinkAeadUtilTest {
    init {
        AeadConfig.register()
    }

    @Test
    fun allAeadTest() {
        val plaintext = "This is aead for Google Tink".encodeToByteArray()
        val associatedData = "This is associated data".encodeToByteArray()
        for (value in TinkAeadType.values()) {
            aeadTest(value.name, plaintext, associatedData)
        }
    }

    private fun aeadTest(alg: String, plaintext: ByteArray, associatedData: ByteArray) {
        val keySetHandle = KeysetHandle.generateNew(KeyTemplates.get(alg))
        val writer = ByteArrayWriter()
        CleartextKeysetHandle.write(keySetHandle, writer)

        val encrypted = TinkAeadUtil.encrypt(plaintext, associatedData, writer.byteArray)
        val decrypted = TinkAeadUtil.decrypt(encrypted, associatedData, writer.byteArray)
        assert(plaintext.contentEquals(decrypted))
    }
}