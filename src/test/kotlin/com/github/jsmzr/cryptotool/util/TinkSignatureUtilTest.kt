package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.constants.TinkMacType
import com.github.jsmzr.cryptotool.tink.ByteArrayWriter
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.signature.SignatureConfig
import org.junit.Test

class TinkSignatureUtilTest {
    init {
        SignatureConfig.register()
    }

    @Test
    fun allSignatureTest() {
        val data = "This is signature for Google Tink".encodeToByteArray()
        for (value in TinkMacType.values()) {
            signatureTest(value.name, data)
        }
    }

    private fun signatureTest(alg: String, data: ByteArray) {
        val keySetHandle = KeysetHandle.generateNew(KeyTemplates.get(alg))
        val priWriter = ByteArrayWriter()
        val pubWriter = ByteArrayWriter()
        CleartextKeysetHandle.write(keySetHandle, priWriter)
        CleartextKeysetHandle.write(keySetHandle.publicKeysetHandle, pubWriter)

        val sign = TinkSignatureUtil.sign(data, priWriter.byteArray)
        TinkSignatureUtil.verify(data, pubWriter.byteArray, sign)
    }
}