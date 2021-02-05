package one.credify.crypto

import crypto.Crypto
import crypto.SigningKey
import crypto.VerificationKey

internal class SigningImpl : KeyPair<SigningKey, VerificationKey>, Signing {
    override val privateKeyAsPKCS8: String?
        get() {
            return mPrivateKey?.string()
        }

    override val privateKeyAsBase64Url: String?
        get() {
            return mPrivateKey?.stringParam()
        }

    override val privateKeyAsBytes: ByteArray?
        get() {
            return mPrivateKey?.bytes()
        }

    override val publicKeyAsPKSC8: String?
        get() {
            return mPublicKey?.string()
        }

    override val publicKeyAsBase64Url: String?
        get() {
            return mPublicKey?.stringParam()
        }

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
        requireNotNull(mPrivateKey, { "Private key must not be null" })

        return mPrivateKey!!.sign(message)
    }

    override fun signBase64(message: String): ByteArray {
        return sign(Crypto.decodeBase64(message))
    }

    override fun signAsBase64(message: ByteArray): String {
        requireNotNull(mPrivateKey, { "Private key must not be null" })

        return mPrivateKey!!.signAsBase64(message)
    }

    override fun signBase64AsBase64(message: String): String {
        return signAsBase64(Crypto.decodeBase64(message))
    }

    override fun verify(signature: ByteArray, message: ByteArray): Boolean {
        requireNotNull(mPublicKey, { "Public key must not be null" })

        return mPublicKey!!.verify(signature, message)
    }

    override fun verifyBase64(signature: String, message: ByteArray): Boolean {
        requireNotNull(mPublicKey, { "Public key must not be null" })

        return mPublicKey!!.verifyBase64(signature, message)
    }

    override fun generateLoginToken(): String {
        requireNotNull(mPrivateKey, { "Private key must not be null" })
        requireNotNull(mPublicKey, { "Public key must not be null" })

        return Crypto.loginToken(mPrivateKey, mPublicKey)
    }

    override fun exportPrivateKey(password: String): String {
        requireNotNull(mPrivateKey, { "Private key must not be null" })

        return mPrivateKey!!.export(password)
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