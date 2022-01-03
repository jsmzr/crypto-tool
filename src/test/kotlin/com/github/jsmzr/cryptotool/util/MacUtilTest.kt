package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.constants.MacType
import org.junit.Test

class MacUtilTest {
    @Test
    fun hmacShaTest() {
        println("----- hmacSHA -----")
        val key = "abcdefg".encodeToByteArray()
        val data = "123456".encodeToByteArray()
        for (value in MacType.values()) {
            printResult(value.name, MacUtil.mac(value.getValue(), key, data))
        }
    }

    private fun printResult(name: String, bytes: ByteArray) {
        println("[${name}] result size: [${bytes.size}]\nresult: [${EncodeUtil.bytesToHexString(bytes)}]")
    }
}