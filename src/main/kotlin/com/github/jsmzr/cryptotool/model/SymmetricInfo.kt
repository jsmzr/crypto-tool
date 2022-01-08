package com.github.jsmzr.cryptotool.model

data class SymmetricInfo(val name: String) {
    val alg: String
    val mode: String
    val padding: String
    init {
        val temp = name.split("/")
        this.alg = temp[0]
        this.mode = temp[1]
        this.padding = temp[2]
    }

    override fun toString(): String {
        return name
    }
}