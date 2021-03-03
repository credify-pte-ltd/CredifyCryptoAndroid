package one.credify.crypto

interface Signing : KeyPairExportable {
    /**
     * Generate a signature of provided [message] message
     *
     * @return a [ByteArray] that was signed
     */
    fun sign(message: ByteArray): ByteArray

    /**
     * Generate a signature of provided [message] message
     *
     * @return a string that was signed and encoded with base 64 [option] format
     */
    fun signAsBase64(message: ByteArray, option: Base64Option): String

    /**
     * Verify a [signature] signature
     *
     * @return true if the [signature] is valid. Otherwise, return false
     */
    fun verify(signature: ByteArray, message: ByteArray): Boolean

    /**
     * Verify a [signature] signature that was encoded with base 64 [option] format
     *
     * @return true if the [signature] is valid. Otherwise, return false
     */
    fun verifyBase64(signature: String, message: ByteArray, option: Base64Option): Boolean

    /**
     * Generate a signature with JWT format by the signing key
     */
    fun generateLoginToken(): String

    /**
     * Generate an approval token needed for OIDC completion.
     */
    fun generateApprovalToken(
        id: String,
        clientId: String,
        scopeList: List<String>,
        offerCode: String?
    ): String

    /**
     * Generate a request token needed for OIDC initiation.
     */
    fun generateRequestToken(
        clientId: String,
        encryptionPublicKey: String,
        scopeList: List<String>,
        offerCode: String?
    ): String
}
