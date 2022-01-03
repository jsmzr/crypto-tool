package com.github.jsmzr.cryptotool.util

import org.junit.Test

class EncodeUtilTest {
    @Test
    fun byte2HexTest() {
        assert("313233343536" == EncodeUtil.bytesToHexString("123456".encodeToByteArray()))
    }

    @Test
    fun hex2byteTest() {
        val utf8str = "123456"
        val hexStr = "313233343536"
        val hexStr1 = "0x313233343536"
        assert(utf8str == String(EncodeUtil.hexStringToBytes(hexStr)!!))
        assert(utf8str == String(EncodeUtil.hexStringToBytes(hexStr1)!!))
    }
}