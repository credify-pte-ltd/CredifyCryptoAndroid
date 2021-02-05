package one.credify.crypto

interface Signing : KeyPairExportable {
    /**
     * Generate a signature of provided [message] message
     *
     * @return a [ByteArray] that was signed
     */
    fun sign(message: ByteArray): ByteArray

    /**
     * Generate a signature of provided [message] message.
     * The [message] was encoded with base 64 url
     *
     * @return a [ByteArray] that was signed
     */
    fun signBase64(message: String): ByteArray

    /**
     * Generate a signature of provided [message] message
     *
     * @return a string that was signed and encoded with base 64 url
     */
    fun signAsBase64(message: ByteArray): String

    /**
     * Generate a signature of provided [message] message.
     * The [message] was encoded with base 64 url
     *
     * @return a string that was signed and encoded with base 64 url
     */
    fun signBase64AsBase64(message: String): String

    /**
     * Verify a [signature] signature
     *
     * @return true if the [signature] is valid. Otherwise, return false
     */
    fun verify(signature: ByteArray, message: ByteArray): Boolean

    /**
     * Verify a [signature] signature that was encoded with base 64 url
     *
     * @return true if the [signature] is valid. Otherwise, return false
     */
    fun verifyBase64(signature: String, message: ByteArray): Boolean

    /**
     * Generate a signature with JWT format by the signing key
     */
    fun generateLoginToken(): String
}
