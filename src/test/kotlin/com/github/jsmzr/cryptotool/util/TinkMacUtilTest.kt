package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.constants.TinkMacType
import com.github.jsmzr.cryptotool.tink.ByteArrayWriter
import com.google.crypto.tink.CleartextKeysetHandle
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.mac.MacConfig
import org.junit.Test

class TinkMacUtilTest {

    init {
        MacConfig.register()
    }

    @Test
    fun allMacTest() {
        val data = "This is mac for Google Tink".encodeToByteArray()
        for (value in TinkMacType.values()) {
            macTest(value.name, data)
        }
    }
    private fun macTest(alg: String, data: ByteArray) {
        val keySetHandle = KeysetHandle.generateNew(KeyTemplates.get(alg))
        val writer = ByteArrayWriter()
        CleartextKeysetHandle.write(keySetHandle, writer)

        val tag = TinkMacUtil.mac(data, writer.byteArray)
        TinkMacUtil.verify(data, writer.byteArray, tag)
    }
}