package com.github.jsmzr.cryptotool.util

import com.github.jsmzr.cryptotool.model.SymmetricInfo
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Symmetric encryption
 * Provide common symmetrical encryption, such as AES DES and 3DES.
 */
object SymmetricUtil {
    val random = SecureRandom()
    /**
     * Symmetric encrypt
     * AES/(ECB|CBC|OFB|CFB|CRT|GCM)/(PKCS5Padding|NoPadding), key length 16,24,32 bytes, iv length as same as block.
     *
     * DES/(ECB|CBC|OFB|CFB|CRT)/(PKCSPadding|NoPadding), key length must be 7 bytes, iv length as same as block(8 bytes).
     *
     * DESede/(ECB|CBC|OFB|CFB|CRT)/(PKCSPadding|NoPadding) key length 14,21 bytes, iv length as same as block(8 bytes).
     * @param info Symmetric info, include alg, mode, padding.
     * @param key If you use AES, then key length be 16,24,32 bytes.
     * @param data If is NoPadding, then data length should be multiple with block (usually AES block is 16,24,32 bytes).
     * @param iv In addition to ECB mode, others need. and iv length is block length.
     * @param tLen If you use GCM mode, then this is a must. (usually Tlen is {96, 104, 112, 120, 128}).
     */
    @JvmStatic
    fun encrypt(info: SymmetricInfo, key: ByteArray, data: ByteArray, iv: ByteArray? = null, tLen: Int = 96): ByteArray {
        val cipher = Cipher.getInstance(info.name)
        when (info.mode) {
            "ECB" -> {
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, info.alg))
            }
            "GCM" -> {
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, info.alg), GCMParameterSpec(tLen, iv))
            }
            else -> {
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, info.alg), IvParameterSpec(iv))
            }
        }
        return cipher.doFinal(data)
    }

    /**
     * Symmetric encrypt
     * AES/(ECB|CBC|OFB|CFB|CRT|GCM)/(PKCS5Padding|NoPadding), key length 16,24,32 bytes, iv length as same as block.
     *
     * DES/(ECB|CBC|OFB|CFB|CRT)/(PKCSPadding|NoPadding), key length must be 7 bytes, iv length as same as block(8 bytes).
     *
     * DESede/(ECB|CBC|OFB|CFB|CRT)/(PKCSPadding|NoPadding) key length 14,21 bytes, iv length as same as block(8 bytes).
     * @param info Symmetric info, include alg, mode, padding.
     * @param key If you use AES, then key length be 16,24,32 bytes.
     * @param data If is NoPadding, then data length should be multiple with block (usually AES block is 16,24,32 bytes).
     * @param iv In addition to ECB mode, others need. and iv length is block length.
     * @param tLen If you use GCM mode, then this is a must. (usually Tlen is {96, 104, 112, 120, 128}).
     */
    @JvmStatic
    fun decrypt(info: SymmetricInfo, key: ByteArray, data: ByteArray, iv: ByteArray? = null, tLen: Int = 96): ByteArray {
        val cipher = Cipher.getInstance(info.name)
        when (info.mode) {
            "ECB" -> {
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, info.alg))
            }
            "GCM" -> {
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, info.alg), GCMParameterSpec(tLen, iv))
            }
            else -> {
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, info.alg), IvParameterSpec(iv))
            }
        }
        return cipher.doFinal(data)
    }

    @JvmStatic
    fun generateKey(info: SymmetricInfo, length: Int): ByteArray {
        val keyGenerator = KeyGenerator.getInstance(info.alg)
        keyGenerator.init(length)
        return keyGenerator.generateKey().encoded
    }

    @JvmStatic
    fun generateIv(length: Int): ByteArray {
        val iv = ByteArray(length)
        random.nextBytes(iv)
        return iv
    }
}