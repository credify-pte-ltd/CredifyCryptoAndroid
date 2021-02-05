package one.credify.crypto

interface KeyPairExportable {
    /**
     * Return private key in PKCS8 format
     */
    val privateKeyAsPKCS8: String?

    /**
     * Return private key that is encoded with base64 url
     */
    val privateKeyAsBase64Url: String?

    /**
     * Return public key in [ByteArray]
     */
    val privateKeyAsBytes: ByteArray?

    /**
     * Return public key in PKCS8 format
     */
    val publicKeyAsPKSC8: String?

    /**
     * Return public key that is encoded with base64 url
     */
    val publicKeyAsBase64Url: String?

    /**
     * Return public key in [ByteArray]
     */
    val publicKeyAsBytes: ByteArray?

    /**
     * Return private key that is encrypted by [password]
     */
    fun exportPrivateKey(password: String): String
}