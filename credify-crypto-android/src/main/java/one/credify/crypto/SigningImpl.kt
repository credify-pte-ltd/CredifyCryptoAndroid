package one.credify.crypto

import crypto.Crypto
import crypto.SigningKey
import crypto.VerificationKey

internal class SigningImpl : KeyPair<SigningKey, VerificationKey>, Signing {
    /**
     * Return private key in PKCS8 format
     */
    override val privateKeyAsPKCS8: String?
        get() {
            return mPrivateKey?.string()
        }

    /**
     * Return private key that is encoded with base64 url
     */
    override val privateKeyAsBase64Url: String?
        get() {
            return mPrivateKey?.stringParam()
        }

    /**
     * Return public key in [ByteArray]
     */
    override val privateKeyAsBytes: ByteArray?
        get() {
            return mPrivateKey?.bytes()
        }

    /**
     * Return public key in PKCS8 format
     */
    override val publicKeyAsPKSC8: String?
        get() {
            return mPublicKey?.string()
        }

    /**
     * Return public key that is encoded with base64 url
     */
    override val publicKeyAsBase64Url: String?
        get() {
            return mPublicKey?.stringParam()
        }

    /**
     * Return public key in [ByteArray]
     */
    override val publicKeyAsBytes: ByteArray?
        get() {
            return mPublicKey?.bytes()
        }

    private constructor() {
        val keyPair = Crypto.generateSigningKeyPair()
        mPrivateKey = keyPair.signingKey
        mPublicKey = keyPair.verificationKey
    }

    private constructor(privateKeyPem: String?, publicKeyPem: String?, password: String? = null) {
        privateKeyPem?.let {
            requireStringNotEmpty(privateKeyPem) { "Invalid private key: $it" }

            mPrivateKey = if (password == null) {
                Crypto.signingKeyFromPEM(privateKeyPem)
            } else {
                Crypto.decryptSigningKey(privateKeyPem, password)
            }
        }

        publicKeyPem?.let {
            requireStringNotEmpty(publicKeyPem) { "Invalid public key: $it" }

            mPublicKey = Crypto.verificationKeyFromPem(publicKeyPem)
        }
    }

    override fun sign(message: ByteArray): ByteArray {
        val privateKey = mPrivateKey

        requireNotNull(privateKey, { "Private key must not be null" })

        return privateKey.sign(message)
    }

    override fun signAsBase64(message: ByteArray, option: Base64Option): String {
        val privateKey = mPrivateKey

        requireNotNull(privateKey, { "Private key must not be null" })

        return when (option) {
            Base64Option.URL -> privateKey.signAsBase64(message)
            else -> CryptoHelper.encodeBase64(sign(message), option)
        }
    }

    override fun verify(signature: ByteArray, message: ByteArray): Boolean {
        val publicKey = mPublicKey

        requireNotNull(publicKey, { "Public key must not be null" })

        return publicKey.verify(signature, message)
    }

    override fun verifyBase64(
        signature: String,
        message: ByteArray,
        option: Base64Option
    ): Boolean {
        val publicKey = mPublicKey

        requireNotNull(publicKey, { "Public key must not be null" })

        return when (option) {
            Base64Option.URL -> publicKey.verifyBase64(signature, message)
            else -> verify(CryptoHelper.decodeBase64(signature, option), message)
        }
    }

    /**
     * Return private key that is encrypted by [password]
     */
    override fun exportPrivateKey(password: String): String {
        requireNotNull(mPrivateKey, { "Private key must not be null" })

        return mPrivateKey!!.export(password)
    }

    override fun generateLoginToken(): String {
        requireNotNull(mPrivateKey, { "Private key must not be null" })
        requireNotNull(mPublicKey, { "Public key must not be null" })

        return Crypto.loginToken(mPrivateKey, mPublicKey)
    }

    /**
     * Generate an approval token needed for OIDC completion.
     */
    override fun generateApprovalToken(
        id: String,
        clientId: String,
        scopeList: List<String>,
        offerCode: String?
    ): String {
        val privateKey = mPrivateKey

        requireNotNull(privateKey, { "Private key must not be null" })

        val scopeString = scopeList.joinToString(" ")
        return Crypto.newApprovalToken(privateKey, id, clientId, scopeString, offerCode)
    }

    /**
     * Generate a request token needed for OIDC initiation.
     */
    override fun generateRequestToken(
        clientId: String,
        encryptionPublicKey: String,
        scopeList: List<String>,
        offerCode: String?
    ): String {
        val privateKey = mPrivateKey

        requireNotNull(privateKey, { "Private key must not be null" })

        val scopeString = scopeList.joinToString(" ")
        return Crypto.newRequestToken(privateKey, clientId, encryptionPublicKey, scopeString, offerCode)
    }

    /**
     * Generate a identity token needed for signing the PII
     */
    override fun generateIdentityToken(entityId: String, source: String, hash: String): String {
        val privateKey = mPrivateKey

        requireNotNull(privateKey, { "Private key must not be null" })

        return Crypto.newIdentityToken(privateKey, entityId, source, hash)
    }

    companion object {
        fun create(): Signing {
            return SigningImpl()
        }

        fun create(privateKeyPem: String, publicKeyPem: String, password: String? = null): Signing {
            return SigningImpl(privateKeyPem, publicKeyPem, password)
        }

        fun createWithPrivateKey(privateKeyPem: String, password: String? = null): Signing {
            return SigningImpl(privateKeyPem, null, password)
        }

        fun createWithPublicKey(publicKeyPem: String, password: String? = null): Signing {
            return SigningImpl(null, publicKeyPem, password)
        }
    }
}