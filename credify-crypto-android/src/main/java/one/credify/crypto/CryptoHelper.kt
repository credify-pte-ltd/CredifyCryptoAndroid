package one.credify.crypto

import android.util.Base64
import crypto.Crypto

object CryptoHelper {
    /**
     * Encode the [message] byte array to string with [option] format
     */
    fun encodeBase64(message: ByteArray, option: Base64Option): String {
        return when (option) {
            Base64Option.DEFAULT -> Base64.encodeToString(message, Base64.DEFAULT)
            Base64Option.URL -> Crypto.encodeBase64(message)
        }
    }

    /**
     * Decode the [message] string(with [option] format) to byte array
     */
    fun decodeBase64(message: String, option: Base64Option): ByteArray {
        return when (option) {
            Base64Option.DEFAULT -> Base64.decode(message, Base64.DEFAULT)
            Base64Option.URL -> Crypto.decodeBase64(message)
        }
    }

    /**
     * Generate a salt
     *
     * @return a [ByteArray]
     */
    fun generateSalt(): ByteArray {
        return Crypto.generateSalt()
    }

    /**
     * Generate a salt and encode it to [option] for mat
     */
    fun generateSaltAsBase64(option: Base64Option): String {
        return when (option) {
            Base64Option.DEFAULT -> Base64.encodeToString(generateSalt(), Base64.DEFAULT)
            Base64Option.URL -> Crypto.generateSaltAsBase64()
        }
    }

    /**
     * Hash [message] byte array
     *
     * @return [ByteArray] after hash
     */
    fun hash(message: ByteArray): ByteArray {
        return Crypto.hash(message)
    }

    /**
     * Hash a string [message]
     *
     * @return [ByteArray] after hash
     */
    fun hash(message: String): ByteArray {
        return hash(message.toByteArray(charset = Charsets.UTF_8))
    }

    /**
     * Hash [message] byte array and return a string with [option] format
     */
    fun hashAsBase64(message: ByteArray, option: Base64Option): String {
        return encodeBase64(hash(message), option)
    }

    /**
     * Hash a string [message] byte array and return a string with [option] format
     */
    fun hashAsBase64(message: String, option: Base64Option): String {
        return hashAsBase64(message.toByteArray(charset = Charsets.UTF_8), option)
    }
}