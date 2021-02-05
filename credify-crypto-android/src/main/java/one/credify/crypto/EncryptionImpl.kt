package one.credify.crypto

import crypto.Crypto
import crypto.EncryptionKey

internal class EncryptionImpl : KeyPair<EncryptionKey, EncryptionKey>, Encryption {
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
        val keyPair = Crypto.generateEncryptionKeyPair()
        mPrivateKey = keyPair.privateKey
        mPublicKey = keyPair.publicKey
    }

    private constructor(privateKeyPem: String?, publicKeyPem: String?, password: String? = null) {
        privateKeyPem?.let {
            requireStringNotEmpty(privateKeyPem) { "Invalid private key: $it" }

            mPrivateKey = if (password == null) {
                Crypto.encryptionPrivateKeyFromPem(privateKeyPem)
            } else {
                Crypto.decryptEncryptionPrivateKey(privateKeyPem, password)
            }
        }

        publicKeyPem?.let {
            requireStringNotEmpty(publicKeyPem) { "Invalid public key: $it" }

            mPublicKey = Crypto.encryptionPublicKeyFromPem(publicKeyPem)
        }
    }

    override fun exportPrivateKey(password: String): String {
        requireNotNull(mPrivateKey, { "Private key must not be null" })

        return mPrivateKey!!.export(password)
    }

    override fun encrypt(message: ByteArray): ByteArray {
        requireNotNull(mPublicKey, { "Public key must not be null" })

        return mPublicKey!!.encrypt(message)
    }

    override fun encryptAsBase64(message: String): String {
        requireNotNull(mPublicKey, { "Public key must not be null" })

        return mPublicKey!!.encryptAsBase64(message.toByteArray(charset = Charsets.UTF_8))
    }

    override fun decrypt(message: ByteArray): ByteArray {
        requireNotNull(mPrivateKey, { "Private key must not be null" })

        return mPrivateKey!!.decrypt(message)
    }

    override fun decryptBase64(message: String): String {
        requireNotNull(mPrivateKey, { "Private key must not be null" })

        return mPrivateKey!!.decryptBase64(message).toString(charset = Charsets.UTF_8)
    }

    companion object {
        fun create(): Encryption {
            return EncryptionImpl()
        }

        fun create(
            privateKeyPem: String,
            publicKeyPem: String,
            password: String? = null
        ): Encryption {
            return EncryptionImpl(privateKeyPem, publicKeyPem, password)
        }

        fun createWithPrivateKey(privateKeyPem: String, password: String? = null): Encryption {
            return EncryptionImpl(privateKeyPem, null, password)
        }

        fun createWithPublicKey(publicKeyPem: String, password: String? = null): Encryption {
            return EncryptionImpl(null, publicKeyPem, password)
        }
    }
}