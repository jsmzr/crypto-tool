package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.constants.HashType
import org.junit.Test
import java.security.Security

class HashUtilTest {

    @Test
    fun algTest() {
        Security.getAlgorithms("Mac").sorted().forEach{ println(it)}
        println("-----")
        Security.getAlgorithms("MessageDigest").sorted().forEach{println(it)}
    }

    @Test
    fun hashTest() {
        val data = "123321".encodeToByteArray()
        for (value in HashType.values()) {
            if (value.getValue().contains("Ripe")) {
                printResult(value.getValue(), HashUtil.hashByRipeMD(value.getValue(), data))
            } else {
                printResult(value.getValue(), HashUtil.hash(value.getValue(), data))
            }
        }
    }

    private fun printResult(name: String, bytes: ByteArray) {
        println("[${name}] result size: [${bytes.size}]\nresult: [${EncodeUtil.bytesToHexString(bytes)}]")
    }
}