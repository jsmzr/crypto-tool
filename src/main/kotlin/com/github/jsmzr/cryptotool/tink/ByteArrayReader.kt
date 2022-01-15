package com.github.jsmzr.cryptotool.tink

import com.google.crypto.tink.KeysetReader
import com.google.crypto.tink.proto.EncryptedKeyset
import com.google.crypto.tink.proto.Keyset
import com.google.protobuf.ExtensionRegistryLite

class ByteArrayReader(byteArray: ByteArray):KeysetReader {
    val byteArray: ByteArray

    init {
        this.byteArray = byteArray
    }
    override fun read(): Keyset {
        return Keyset.parseFrom(byteArray, ExtensionRegistryLite.getEmptyRegistry())
    }

    override fun readEncrypted(): EncryptedKeyset {
        return EncryptedKeyset.parseFrom(byteArray, ExtensionRegistryLite.getEmptyRegistry());
    }
}