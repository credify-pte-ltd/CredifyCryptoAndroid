package one.credify.crypto

class KeyCreator {
    private var mPrivateKey: String? = null
    private var mPublicKey: String? = null
    private var mPassword: String? = null

    /**
     * [privateKey] private key restored from a pem file (PKCS#8)
     */
    fun setPrivateKey(privateKey: String): KeyCreator {
        mPrivateKey = privateKey
        return this
    }

    /**
     * [publicKey] public key restored from a pem file (PKCS#8)
     */
    fun setPublicKey(publicKey: String): KeyCreator {
        mPublicKey = publicKey
        return this
    }

    /**
     * [password] password to decrypt the private key if it is encrypted by the [password] before
     */
    fun setPassword(password: String): KeyCreator {
        mPassword = password
        return this
    }

    /**
     * Create or restore signing key
     */
    fun createSigningKey(): Signing {
        val privateKey = mPrivateKey
        val publicKey = mPublicKey
        val password = mPassword

        return when {
            privateKey != null && publicKey != null -> {
                SigningImpl.create(privateKey, publicKey, password)
            }
            privateKey != null -> {
                SigningImpl.createWithPrivateKey(privateKey, password)
            }
            publicKey != null -> {
                return SigningImpl.createWithPublicKey(publicKey, password)
            }
            else -> SigningImpl.create()
        }
    }

    /**
     * Create or restore encryption key
     */
    fun createEncryptionKey(): Encryption {
        val privateKey = mPrivateKey
        val publicKey = mPublicKey
        val password = mPassword

        return when {
            privateKey != null && publicKey != null -> {
                EncryptionImpl.create(privateKey, publicKey, password)
            }
            privateKey != null -> {
                EncryptionImpl.createWithPrivateKey(privateKey, password)
            }
            publicKey != null -> {
                return EncryptionImpl.createWithPublicKey(publicKey, password)
            }
            else -> EncryptionImpl.create()
        }
    }
}