package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.constants.TinkDaeadType
import com.github.jsmzr.cryptotool.tink.ByteArrayWriter
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.daead.DeterministicAeadConfig
import org.junit.Test

class TinkDaeadUtilTest {
    init {
        DeterministicAeadConfig.register()
    }

    @Test
    fun allDaeadTest() {
        val plaintext = "This is daead for Google Tink".encodeToByteArray()
        val associatedData = "This is dassociated data".encodeToByteArray()
        for (value in TinkDaeadType.values()) {
            daeadTest(value.name, plaintext, associatedData)
        }
    }

    private fun daeadTest(alg: String, plaintext: ByteArray, associatedData: ByteArray) {
        val keySetHandle = KeysetHandle.generateNew(KeyTemplates.get(alg))
        val writer = ByteArrayWriter()
        CleartextKeysetHandle.write(keySetHandle, writer)

        val encrypted = TinkDaeadUtil.encrypt(plaintext, associatedData, writer.byteArray)
        val decrypted = TinkDaeadUtil.decrypt(encrypted, associatedData, writer.byteArray)
        assert(plaintext.contentEquals(decrypted))
    }
}