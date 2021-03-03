package one.credify.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import junit.framework.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class EncryptionTest {
    private val mPassword = "Abc@123"
    private val mMessage = "123 @#$ test **( Túng' ssh &"

    @Test
    fun generateKeyTest() {
        val key = KeyCreator().createEncryptionKey()

        assertNotNull(key.privateKeyAsPKCS8)
        assertNotNull(key.privateKeyAsPKCS8)
    }

    @Test
    fun encryptPrivateKeyTest() {
        val key = KeyCreator().createEncryptionKey()

        val encryptPrivateKey = key.exportPrivateKey(mPassword)

        assertNotNull(encryptPrivateKey)
    }

    @Test
    fun generateAndImportKeyTest() {
        val key = KeyCreator().createEncryptionKey()
        val privateKeyPem = key.privateKeyAsPKCS8
        val publicKeyPem = key.publicKeyAsPKSC8

        val importKey = KeyCreator()
            .setPrivateKey(privateKeyPem!!)
            .setPublicKey(publicKeyPem!!)
            .createEncryptionKey()

        assertEquals(privateKeyPem, importKey.privateKeyAsPKCS8)
        assertEquals(publicKeyPem, importKey.publicKeyAsPKSC8)
    }

    @Test
    fun encryptAndDecryptPrivateKeyWithPasswordTest() {
        val key = KeyCreator().createEncryptionKey()
        val keyPem = key.privateKeyAsPKCS8

        // Decrypt
        val encryptedPrivateKey = key.exportPrivateKey(mPassword)
        assertNotNull(encryptedPrivateKey)
        assertNotNull(keyPem)

        // Decrypt the encrypted private key
        val decryptedKey = KeyCreator()
            .setPrivateKey(encryptedPrivateKey)
            .setPassword(mPassword)
            .createEncryptionKey()

        assertNotNull(decryptedKey)
        assertEquals(keyPem, decryptedKey.privateKeyAsPKCS8)

        // Null because we only input the private key
        assertNull(decryptedKey.publicKeyAsPKSC8)
    }

    @Test
    fun encryptAndDecryptBase64UrlTest() {
        val key = KeyCreator().createEncryptionKey()

        // Encrypt
        val encryptedMessage = key.encryptAsBase64(mMessage, Base64Option.URL)

        // Decrypt
        val decryptedMessage = key.decryptBase64(encryptedMessage, Base64Option.URL)

        assertEquals(decryptedMessage, mMessage)
    }

    @Test
    fun encryptAndDecryptBase64DefaultTest() {
        val key = KeyCreator().createEncryptionKey()

        // Encrypt
        val encryptedMessage = key.encryptAsBase64(mMessage, Base64Option.DEFAULT)

        // Decrypt
        val decryptedMessage = key.decryptBase64(encryptedMessage, Base64Option.DEFAULT)

        assertEquals(decryptedMessage, mMessage)
    }
}