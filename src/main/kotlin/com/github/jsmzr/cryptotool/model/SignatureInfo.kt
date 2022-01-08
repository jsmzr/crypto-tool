package com.github.jsmzr.cryptotool.model

data class SignatureInfo(val name: String) {
    val key: String

    init {
        val tmp = name.substring(name.lastIndexOf("with") + 4)
        key = if (tmp == "ECDSA") {
            "EC"
        } else {
            tmp
        }
    }

    override fun toString(): String {
        return name
    }
}
