package one.credify.crypto

interface Encryption : KeyPairExportable {
    fun encrypt(message: ByteArray): ByteArray

    fun encryptAsBase64(message: String): String

    fun decrypt(message: ByteArray): ByteArray

    fun decryptBase64(message: String): String
}