package com.github.jsmzr.cryptotool.constants

enum class AsymmetricType(value: String) {
    RSA("RSA");

    private val value: String

    init {
        this.value = value
    }

    fun getValue(): String {
        return this.value
    }
}