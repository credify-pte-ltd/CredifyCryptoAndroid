package one.credify.crypto

import crypto.Crypto

object CryptoHelper {
    fun encodeBase64(message: ByteArray): String {
        return Crypto.encodeBase64(message)
    }

    fun decodeBase64(message: String): ByteArray {
        return Crypto.decodeBase64(message)
    }

    fun generateSalt(): ByteArray {
        return Crypto.generateSalt()
    }

    fun generateSaltAsBase64(): String {
        return Crypto.generateSaltAsBase64()
    }

    fun hash(message: ByteArray): ByteArray {
        return Crypto.hash(message)
    }

    fun hashAsBase64(message: ByteArray): String {
        return Crypto.encodeBase64(hash(message))
    }
}