package com.github.jsmzr.cryptotool.tink

import com.google.crypto.tink.KeysetWriter
import com.google.crypto.tink.proto.EncryptedKeyset
import com.google.crypto.tink.proto.Keyset
import java.io.ByteArrayOutputStream

class ByteArrayWriter(): KeysetWriter {
    lateinit var byteArray: ByteArray

    override fun write(keyset: Keyset) {
        val outputStream = ByteArrayOutputStream()
        keyset.writeTo(outputStream)
        byteArray = outputStream.toByteArray()
    }

    override fun write(keyset: EncryptedKeyset) {
        val outputStream = ByteArrayOutputStream()
        keyset.writeTo(outputStream)

        byteArray = outputStream.toByteArray()

    }

}