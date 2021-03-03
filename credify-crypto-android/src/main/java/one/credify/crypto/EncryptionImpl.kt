package one.credify.crypto

import crypto.Crypto
import crypto.EncryptionKey

internal class EncryptionImpl : KeyPair<EncryptionKey, EncryptionKey>, Encryption {
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

    /**
     * Return private key that is encrypted by [password]
     */
    override fun exportPrivateKey(password: String): String {
        requireNotNull(mPrivateKey, { "Private key must not be null" })

        return mPrivateKey!!.export(password)
    }

    /**
     * Encrypt [message]
     *
     * @return [ByteArray] that was encrypted
     */
    override fun encrypt(message: ByteArray): ByteArray {
        val publicKey = mPublicKey

        requireNotNull(publicKey, { "Public key must not be null" })

        return publicKey.encrypt(message)
    }

    /**
     * Encrypt [message] in plain text
     *
     * @return a string in base 64 with [option] format that was encrypted
     */
    override fun encryptAsBase64(message: String, option: Base64Option): String {
        val publicKey = mPublicKey

        requireNotNull(publicKey, { "Public key must not be null" })

        // String to ByteArray
        val messageByteArr = message.toByteArray(charset = Charsets.UTF_8)

        return when (option) {
            Base64Option.URL -> publicKey.encryptAsBase64(messageByteArr)
            else -> CryptoHelper.encodeBase64(encrypt(messageByteArr), option)
        }
    }

    /**
     * Decrypt [message]
     *
     * @return [ByteArray] that was decrypted
     */
    override fun decrypt(message: ByteArray): ByteArray {
        val privateKey = mPrivateKey

        requireNotNull(privateKey, { "Private key must not be null" })

        return privateKey.decrypt(message)
    }

    /**
     * Decrypt [message] in base 64 [option] format
     *
     * @return a string that was decrypted
     */
    override fun decryptBase64(message: String, option: Base64Option): String {
        val privateKey = mPrivateKey

        requireNotNull(privateKey, { "Private key must not be null" })

        return when (option) {
            Base64Option.URL -> privateKey.decryptBase64(message).toString(charset = Charsets.UTF_8)
            else -> decrypt(CryptoHelper.decodeBase64(message, option)).toString(
                charset = Charsets.UTF_8
            )
        }
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