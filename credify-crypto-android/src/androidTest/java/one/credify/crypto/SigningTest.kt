package one.credify.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import junit.framework.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.*

@RunWith(AndroidJUnit4::class)
class SigningTest {
    private val mPassword = "Abc@123"
    private val mMessage = "message to sign"

    @Test
    fun generateKeyTest() {
        val key = KeyCreator().createSigningKey()

        assertNotNull(key.privateKeyAsPKCS8)
        assertNotNull(key.privateKeyAsPKCS8)
    }

    @Test
    fun encryptPrivateKeyTest() {
        val key = KeyCreator().createSigningKey()

        val encryptPrivateKey = key.exportPrivateKey(mPassword)

        assertNotNull(encryptPrivateKey)
    }

    @Test
    fun generateAndImportKeyTest() {
        val key = KeyCreator().createSigningKey()
        val privateKeyPem = key.privateKeyAsPKCS8
        val publicKeyPem = key.publicKeyAsPKSC8

        val importKey = KeyCreator()
            .setPrivateKey(privateKeyPem!!)
            .setPublicKey(publicKeyPem!!)
            .createSigningKey()

        assertEquals(privateKeyPem, importKey.privateKeyAsPKCS8)
        assertEquals(publicKeyPem, importKey.publicKeyAsPKSC8)
    }

    @Test
    fun encryptAndDecryptPrivateKeyWithPasswordTest() {
        val key = KeyCreator().createSigningKey()
        val keyPem = key.privateKeyAsPKCS8

        // Decrypt
        val encryptedPrivateKey = key.exportPrivateKey(mPassword)
        assertNotNull(encryptedPrivateKey)
        assertNotNull(keyPem)

        // Decrypt the encrypted private key
        val decryptedKey = KeyCreator()
            .setPrivateKey(encryptedPrivateKey)
            .setPassword(mPassword)
            .createSigningKey()

        assertNotNull(decryptedKey)
        assertEquals(keyPem, decryptedKey.privateKeyAsPKCS8)

        // Null because we only input the private key
        assertNull(decryptedKey.publicKeyAsPKSC8)
    }

    @Test
    fun signAndVerifyBase64UrlTest() {
        val key = KeyCreator().createSigningKey()
        val message = mMessage.toByteArray(charset = Charsets.UTF_8)

        // Encrypt
        val signedMessage = key.signAsBase64(message, Base64Option.URL)

        // Decrypt
        val result = key.verifyBase64(signedMessage, message, Base64Option.URL)

        assertEquals(result, true)
    }

    @Test
    fun signAndVerifyBase64DefaultTest() {
        val key = KeyCreator().createSigningKey()
        val message = mMessage.toByteArray(charset = Charsets.UTF_8)

        // Encrypt
        val signedMessage = key.signAsBase64(message, Base64Option.DEFAULT)

        // Decrypt
        val result = key.verifyBase64(signedMessage, message, Base64Option.DEFAULT)

        assertEquals(result, true)
    }

    @Test
    fun listStringToStringTest() {
        val result = "fun private public test Kotlin"
        val list = listOf("fun", "private", "public", "test", "Kotlin")

        val listToString = list.joinToString(" ")

        assertEquals(result, listToString)
    }

    @Test
    fun generateApprovalTokenTest() {
        val key = KeyCreator().createSigningKey()
        val id = UUID.randomUUID().toString()
        val clientId = UUID.randomUUID().toString()
        val scopeList = listOf("profile", "email", "address")
        val offerCode = "tiki-code"

        val approvalToken = key.generateApprovalToken(id, clientId, scopeList, offerCode)

        assertNotNull(approvalToken)
    }

    @Test
    fun generateRequestTokenTest() {
        val signingKey = KeyCreator().createSigningKey()
        val encryptionKey = KeyCreator().createEncryptionKey()
        val clientId = UUID.randomUUID().toString()
        val scopeList = listOf("profile", "email", "address")
        val offerCode = "tiki-code"

        val requestToken = signingKey.generateRequestToken(
            clientId,
            encryptionKey.publicKeyAsPKSC8!!,
            scopeList,
            offerCode
        )

        assertNotNull(requestToken)
    }
}