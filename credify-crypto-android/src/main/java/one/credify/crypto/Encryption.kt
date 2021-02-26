package one.credify.crypto

interface Encryption : KeyPairExportable {
    /**
     * Encrypt [message]
     *
     * @return [ByteArray] that was encrypted
     */
    fun encrypt(message: ByteArray): ByteArray

    /**
     * Encrypt [message] in plain text
     *
     * @return a string in base 64 with [option] format that was encrypted
     */
    fun encryptAsBase64(message: String, option: Base64Option): String

    /**
     * Decrypt [message]
     *
     * @return [ByteArray] that was decrypted
     */
    fun decrypt(message: ByteArray): ByteArray

    /**
     * Decrypt [message] in base 64 [option] format
     *
     * @return a string that was decrypted
     */
    fun decryptBase64(message: String, option: Base64Option): String
}