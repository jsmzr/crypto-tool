package com.github.jsmzr.cryptotool.util

import org.bouncycastle.crypto.digests.RIPEMD128Digest
import org.bouncycastle.crypto.digests.RIPEMD160Digest
import org.bouncycastle.crypto.digests.RIPEMD256Digest
import org.bouncycastle.crypto.digests.RIPEMD320Digest
import java.security.MessageDigest
import kotlin.test.fail

object HashUtil {
    @JvmStatic
    fun hash(alg: String, bytes: ByteArray): ByteArray {
        return MessageDigest.getInstance(alg).digest(bytes)
    }

    @JvmStatic
    fun hashByRipeMD(alg: String, bytes: ByteArray): ByteArray {
        val digest = when (alg) {
            "RipeMD-128" -> {
                RIPEMD128Digest()
            }
            "RipeMD-160" -> {
                RIPEMD160Digest()
            }
            "RipeMD-256" -> {
                RIPEMD256Digest()
            }
            "RipeMD-320" -> {
                RIPEMD320Digest()
            }
            else -> {
                fail("not found alg: [${alg}]")
            }
        }
        digest.update(bytes, 0, bytes.size)
        val res = ByteArray(digest.digestSize)
        digest.doFinal(res, 0)
        return res
    }
}