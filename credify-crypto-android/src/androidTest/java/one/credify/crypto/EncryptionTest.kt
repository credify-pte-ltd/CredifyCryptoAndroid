package one.credify.crypto

import androidx.test.ext.junit.runners.AndroidJUnit4
import junit.framework.Assert.*
import org.junit.Assert
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

    @Test
    fun decryptedLongMessageTest() {
        val data = "eyJpbWdzIjp7ImltZ19mcm9udCI6ImlkZzIwMjExMDI5LWNmM2FhOGJhLTExODMtN2JhMC1lMDUzLTYzMTk5ZjBhYjY4ZS9JREcwMV82ZTllYWIzMi0zOGI5LTExZWMtYTE1Mi02NzM3MjI4ODllNTcifSwibWVzc2FnZSI6IklERy0wMDAwMDAwMCIsInNlcnZlcl92ZXJzaW9uIjoiMS4zLjExIiwib2JqZWN0Ijp7Im5hbWVfcHJvYiI6MC45OTk5OTk1NjkwMTI1Njg2LCJvcmlnaW5fbG9jYXRpb24iOiItIiwibXNnIjoiT0siLCJnZW5kZXIiOiItIiwiZXhwaXJlX3dhcm5pbmciOiJubyIsIm5hdGlvbl9zbG9nYW4iOiLEkOG7mWMgbOG6rXAgLSBU4buxIGRvIC0gSOG6oW5oIHBow7pjIiwidmFsaWRfZGF0ZV9wcm9iIjowLjk5OTk5OTk2NDkzODQ0NDIsIm5hdGlvbl9wb2xpY3kiOiJD4buYTkcgSMOSQSBYw4MgSOG7mEkgQ0jhu6YgTkdIxKhBIFZJ4buGVCBOQU0iLCJvcmlnaW5fbG9jYXRpb25fcHJvYiI6MCwiZ2VuZXJhbF93YXJuaW5nIjpbXSwiY29ybmVyX3dhcm5pbmciOiJubyIsInZhbGlkX2RhdGUiOiIwOS8wNC8yMDI5IiwiaXNzdWVfZGF0ZSI6IjA5LzA0LzIwMTkiLCJpZF9mYWtlX3Byb2IiOjAsImNoZWNraW5nX3Jlc3VsdF9mcm9udCI6eyJjb3JuZXJfY3V0X3Jlc3VsdCI6IjAiLCJlZGl0ZWRfcHJvYiI6MC4wNjMzMzM0MjE5NDU1NzE5LCJjaGVja19waG90b2NvcGllZF9wcm9iIjowLCJyZWNhcHR1cmVkX3Jlc3VsdCI6IjAiLCJjb3JuZXJfY3V0X3Byb2IiOlswLDAsMCwwXSwiY2hlY2tfcGhvdG9jb3BpZWRfcmVzdWx0IjoiMCIsImVkaXRlZF9yZXN1bHQiOiIwIiwicmVjYXB0dXJlZF9wcm9iIjowLjA5NjI5MDk5ODE2MDgzOTA4fSwicmFuayI6IkIyIiwiaWQiOiI3OTAxOTAwNTk0NjAiLCJjaXRpemVuX2lkX3Byb2IiOjAsImlkX3Byb2JzIjoiWzEuMCwgMC45OTk5OTk4ODA3OTA3MTA0LCAxLjAsIDEuMCwgMS4wLCAxLjAsIDEuMCwgMC45OTk5OTk3NjE1ODE0MjA5LCAxLjAsIDEuMCwgMS4wLCAxLjBdIiwiaXNzdWVfcGxhY2UiOiJC4buYIEdUVlQiLCJiaXJ0aF9kYXlfcHJvYiI6MC45OTk5OTk5NDAzOTUzNTUyLCJyZWNlbnRfbG9jYXRpb24iOiJUaMO0biAxXG5YLiBDw7kgQuG7iywgSC4gQ2jDonUgxJDhu6ljLCBULiBCw6AgUuG7i2EgLSBWxaluZyBUw6B1IiwiaWRfZmFrZV93YXJuaW5nIjoibm8iLCJuYW1lX3Byb2JzIjpbMSwxLDEsMSwxLDAuOTk5OTk4MDkyNjUxMzY3MiwwLjk5OTk5OTg4MDc5MDcxMDQsMSwxLDAuOTk5OTk2OTAwNTU4NDcxNywxLDAuOTk5OTk5NjQyMzcyMTMxMywwLjk5OTk5OTg4MDc5MDcxMDRdLCJ0eXBlX2lkIjo0LCJjYXJkX3R5cGUiOiJHSeG6pFkgUEjDiVAgTMOBSSBYRS9EUklWRVInUyBMSUNFTlNFIiwicXVhbGl0eV9mcm9udCI6eyJibHVyX3Njb3JlIjowLjczNDgsImJyaWdodF9zcG90X3BhcmFtIjp7ImF2ZXJhZ2VfaW50ZW5zaXR5IjoxNjguMTcsImJyaWdodF9zcG90X3RocmVzaG9sZCI6MjMwLCJ0b3RhbF9icmlnaHRfc3BvdF9hcmVhIjowfSwibHVtaW5hbmNlX3Njb3JlIjowLjY1NjksImZpbmFsX3Jlc3VsdCI6eyJiYWRfbHVtaW5hbmNlX2xpa2VsaWhvb2QiOiJ1bmxpa2VseSIsImxvd19yZXNvbHV0aW9uX2xpa2VsaWhvb2QiOiJ1bmxpa2VseSIsImJsdXJyZWRfbGlrZWxpaG9vZCI6Imxpa2VseSIsImJyaWdodF9zcG90X2xpa2VsaWhvb2QiOiJ1bmxpa2VseSJ9LCJicmlnaHRfc3BvdF9zY29yZSI6MCwicmVzb2x1dGlvbiI6WzQ0MSw3MjBdfSwiYmlydGhfZGF5IjoiMTUvMTAvMTk5MCIsImlzc3VlX2RhdGVfcHJvYiI6MC45OTk5ODQ3NDg0MDQ2MDE1LCJjaXRpemVuX2lkIjoiLSIsInJlY2VudF9sb2NhdGlvbl9wcm9iIjowLjk5OTk5NTQ3NjEzNDcyODQsImlzc3VlX3BsYWNlX3Byb2IiOjEsImdlbmRlcl9wcm9iIjowLCJuYXRpb25hbGl0eSI6IlZJ4buGVCBOQU0iLCJuYW1lIjoiTMOKIFFV4buQQyBHSU9BTiIsInRhbXBlcmluZyI6eyJpc19sZWdhbCI6InllcyIsIndhcm5pbmciOltdfSwiaWRfcHJvYiI6MC45OTk5OTk5Njg2MjkxMzQzfSwic3RhdHVzQ29kZSI6MjAwLCJjaGFsbGVuZ2VDb2RlIjoiMTExMTEifQ=="

        // Key for encrypting
        val encryptKey = KeyCreator()
            .setPublicKey(Constant.ENCRYPTION_PUBLIC_KEY)
            .createEncryptionKey()

        // Key for decrypting
        val key = KeyCreator()
            .setPrivateKey(Constant.ENCRYPTED_ENCRYPTION_PRIVATE_KEY)
            .setPassword(Constant.PASSWORD)
            .createEncryptionKey()

        // Encrypt
        val encryptData = encryptKey.encryptAsBase64(data, Base64Option.URL)

        // Decrypt
        val decryptedData = key.decryptBase64(encryptData, Base64Option.URL)

        Assert.assertEquals(data, decryptedData)
    }
}