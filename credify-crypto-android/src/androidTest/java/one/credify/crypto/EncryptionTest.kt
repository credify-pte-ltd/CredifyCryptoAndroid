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

    private val mKeyPem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
            "MIIHcDBaBgkqhkiG9w0BBQ0wTTAsBgkqhkiG9w0BBQwwHwQIefrtRe+C9RQCAicQ\n" +
            "AgEgMAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBDMgKqXkwqiKQv3/BWVgSwf\n" +
            "BIIHEGVPTAuhpa8Euh9FROS0/q1Qi8dO9GAPnfP9x6nDzK7iYoOkTNqC39EWhXA8\n" +
            "VtC0FtkhIGEsrXYO951DWJQNMrtxVRM/Mk7u+oM4cXEl0aHwZh1vAnFnpbKpVfmK\n" +
            "bTevhkmT+tfz5JiTpHtBs9qpi5v51g2Ba5PD1e4jq64GYL8/4YxfdFrigKlk5mt4\n" +
            "YfOv3x2lUPLFJ6KPeaIAM92BUmUos1jsm/thCi1q/lA2UIAZIlubUIt2zJlLDSGy\n" +
            "dYzgXADXAJV6/6X9OYztb60VAsN0/Xu70AJ4GqkLTo+Or4QZipB43R5nJ28M6Td9\n" +
            "OJUJOzbRBhCp63EwrtNWxcuqUR8ovlJe4dXXj/xJVKfJURdKR/HAQRQ0YRTvUaXL\n" +
            "ila8IUCxZRaZw3/6QtbGBRf0rf8eH0VQs9V+9IXC6cIVt+lxw2eHmbF1B0L9Ytio\n" +
            "Do+ZrhmIUGgM4VSyg9tDSoHzOUnscgyubVF4eCe3285xvuh3vTAOhz6QjOVpqqTC\n" +
            "AnVinKxYVV9mKn71pCkiuZSOw7WcLvZ2Q/iDeOmwpE0eaH2Yp3z0GX9Mw4KvGqIJ\n" +
            "fnJ789NUjKL7hJhMcr4p06Pg/yEpp6jdHOLAgTmEFf4g+xAX7Tfh2MC4rveoz3cv\n" +
            "z9a8h77z0hgn62kky6YmioZwrxNFlxqHB0TlwT1YPbI8E9JFzf+YbTslshil8uVm\n" +
            "KQhsRWdw4Njf48+2IbCWZa9nROJXv0oOcrzGLMYHIoGaYohTW8xqwfCGOXKAC8yU\n" +
            "aYqZozzHK3nKoVabVnogomZYMF8YLGFP5e0Xqsty8pbhGF6pAcsHbWtqwE7HTcax\n" +
            "ajyLtsEj+NLSivqG5+qJwWES/LrxQrhwFB0zV9MXx+RPlc1siW3I+P/kOtKzPnWm\n" +
            "BKuflTHtiK1OMZIji+iYSRBxrt8cwsdPSyI6QcZIUG/PG2jK6KyjX4sUiloYZFTc\n" +
            "VOmr3OYyTx2NoDD0FxcObK50jqexLNsl7bgi7PKHTy2JUQTIHjkxiU3LMWnOWuHK\n" +
            "twrG+QOUCuqD8K7YoHghU+QFBZJ6K4mQGa2NLuE5P3dPFSVkd0kPIUxbOhL+IQbj\n" +
            "jmi6u504jB2Ga8CAWmG0BYJAadpjVNPd+zEQYqWGnUrtkign0iiGb9hzMDyHD9/9\n" +
            "3jCn4Ev/3GyqusQtbrxbPslwM6DmCjaHhmPF/YAWeVDnrpE3xkIktbhOlzVWeb9Y\n" +
            "yUPhCjcd36dQl9Dz8vQ6vIpXdO2tqMhBJBlFIBj37aHHwD1OrS8ouL6/O0Leu3rY\n" +
            "9Zz4+S32FmD9N0TT5p+GIKgiH9LGGxf3ZfHeM2Gn/KG4q7z9tWWMpmVL7KtykEXQ\n" +
            "oJ93vyt0nX0iqWq/w4cu8zSgm6OyIxDXDpufmLIAafZK8Shc1W8thpzye50dmccI\n" +
            "WjZQfSSCzzM7cvf/ma2/zhAkAN9uMiIhuZ7iXEOnBfoebIkbIqZ5DzEo6BXaOWgV\n" +
            "o32JA6t8AXPTbrWEJJeFR1ih2e8IJkvPyOQ3Lr2V/uelhvpyxmMv1fy5z0a7o+WQ\n" +
            "6A48r/e3UVr0lJJvS8TiEGpNJUO4uNNOh6vgjWC+687QqP5fCZv6bvDaOknsrmlu\n" +
            "gcgs4s/ce62Q9txC7ql7KlN6oF9M3vlBgq2sjRHL4jVOL7JW2sRXQdnkaiuO9Q2H\n" +
            "nU3AW00Mca+7WnNrtOFR98OJJ6TggIHkeXksYRPiMg7fo7ePdom+wjx13RHkijdr\n" +
            "M7DP7HxH7rMv9MZhiwEkTpMjgR7U3ExfYCbR64+6WaFzQQFExeOWKpX13EvVtacO\n" +
            "Fm855WXwbuCM/HXFWB8A/L6TC5fsndqqxOECb1g1l5qQ/T6yb2/qF90cyyN4lcLN\n" +
            "rVjTrMeDl7zA/A9Y1SFNVyFFQBzTTIw8OPdtqZeofnyYsepvSXZ88N9ZhRPRtSU/\n" +
            "BwrX0Myicv0UujjrJpdohfDlFDpm6YDNBT7OHlWoxNMwQ+PfMYtXENoUhryeSQjb\n" +
            "xjlIZhryogRWgUUCxx7jkOPB1zVaxQb8eaj25T56qfhdgHr7hZe8HztGqqogA2aU\n" +
            "xYG/ZJ5cTFa4ShjZDSV/rAXZ96CAGsOWMOdebIDxX635cQ3qI3SzVa+y2xWBxNE/\n" +
            "8qODGywEIVZynU6cUWVD+JJynQtmK1g5afUtYtnNN0zzH6PNZ7re31zrR4OetR2g\n" +
            "rzdWHmXt7EMLB+J7fQ5osJVou0dHs0Q4MMeJJlTdYRunsMToEhy6UX32/aIGY6Cy\n" +
            "iL8CMyUnxdcuyXtxQNknzUUyGNWxVErR4mnp4bEiQV6b+rR36WTfVu2YCpe7IlK0\n" +
            "uSE7JPOawOZ+JQji8REw5H8Su8I7Bx+uP85zfMJ5hy2sJ7VYFZowyAzBh6W2+wQe\n" +
            "Fq+tKSADMFjOQ1B3u/zX1yH3NWHfDCYb4NXwfsLOTIKrt+bp\n" +
            "-----END ENCRYPTED PRIVATE KEY-----\n"

    @Test
    fun decryptedLongMessageTest() {
        val password = "123456aA@"
        val data = "ZrF-XwGNiZmOyXpOBqE_X7woKU0quUeTduk-bLm4E8u0KZvgYKDG4hZlDCDke2dG6lLzuRXTC2BkfRC92JaB0afkICv7X9h9QwO36dZsTtZEzpvphXjNxnGrqgxr3V87psupun20ArGpdgCBOJ1xYebXONmK-jh2NAEEZ3MvfwH1lgy5FA2gnept3SFBM1P52P_KmHQ78GgJC6lkhSt3vPyaKsTSWZDJ-p235YAvyg8nh4dGbf6Ts2HqC85DwEKB6ETZLeC7h4Tab2iwsqCnuDjnQTgBj5_26y5y0So-Qvbnr9CPgg1UDpaagQmLDACLzJeegVBJdjGoonn9oim9j-NvlIB6Fl-4u2sqLI9gt39rhztmc8JcRtJwER9joPHfxslisdZRPSrcm7kiz5b0XUpqudp1IFE77GshotXYtcR1QR6RgVp_XbyHR2U21QI6rcwAgsINrnIOmjdxfa3v128J9ZznrcWLmHWtFqNStfZclyS0cGDQ8MeyeSe2qBNQYWUzuE5JgX97v_igL9HLFqOCm9jyfMD8twpbo-gPFX9Y_xuEPleJVESi-gnGd2GgJve0kASAlEz4ErnxiwlNWdDO6Bc7W1dryVFXllN7SoE8NcDRZOPlSK_aX6fpzLBTe89xJzOj_PaGfHekkNVhB7zbDGBhnK-5OSQXpOnnHQBMhEZOTAMTylo7sYUjfsVTT6gDttt0SEATrO8nhye5ZO2RXGs5uidopOlfDf3WKrvhAk3wmJX8tog1RysHxPUXaibpHh_qnq0F2RUhad_onVydvHiAxSi98AF1qWm6uzp7XQNvRCvj8Flp_pUezP7v4GyyYmNuYwaSgb5s9VHexxMEHm3QAJQlLf8zCMWmtPxKAl61k0IMJqfm7tK5WLAwAQxIXXm8AWFbKVoWCwKV80oQ-NAKrHnX5-6gZLdZf9WqGPt7EE5A_YkwMfi1-faqIFux9iPFtW83-IJ73nUXi5Qo2UojyqvvPpReChM9326aJ8_7kOAIoZ1DyfLJut9hblqGyQgZBTMPCAOADVbN0P_tRzUIHY03wU2zrdbOcds4kvmnvsQ3Rd4Rl3vehBIpd-D7V9MQkHMTghQxwUTIHxRQkkJwcdbUuM2s4--J-vDJvFAALINHhZxHZ43ltaMBVao6y9eq2mJTnMHv-If1uCsV1ZhATT0t5jJ2H_keL7qxZ8ISztQGyn7YXjDXu9EymEJC1QbLnsPU49HKD1BnFq1-pDVyaysaPYjkDuOuWPHknxxHUTTrEXyFbQl2PsJk19YZ871PpEpS7cnICl891OPRIEGWHAGBWuA7MMNteQ8XVOgbD09KO5bOyAT_g1VOJLWdacxMFN8ubSp4A7R1LZgBbwNEQrF7lN6pBCYnm9vmI0Ra7nNvu6Qm2sBvzBOoSalEmlOvdTD1O6By0FSmk-ez2bVIR-nzK7XydhSkQMldfztTc-KvkO-b18wXWmLer1alp36r_v0s-XeaA4qCMr4LXVmA5cCEn1JB5rHluvMpBJ3WUr0aPe_Y5zmWuGyFmGQqdDeXqVDxMp9uniABXDbwKXtRZcAjFQbmtjNSVeMCKwDGOseF3tjM6uiU5yUq99qFtCbRDU2v4jaqexVxDc3mCnFeVw3I65zAe8axYoFQEroEJOCBPgV3h1j3zVV31Qsu93qdKkpAowpkMqRzUaCkiGJKTm7kaAFPlpyeeqbqmiEnGQni9j_Oh8D-BOQFQE0nreEwxBzO0JUWDXxD7xq9KFf0U4ZFei4bhNFqQDAcWQs-KAS70ppHCLHvGIoTPRILyQVFv7QYa1molmkbBRwZ5MZ_RK8gxNTAnr0XgFHqOv5ivR43RQVKA2aSmuODox0WlXkbUcgXZVpUyar2cGgIsFooRtXj2oY1CK2pPAUvP6Rky2EJwfR9glDSbvXiOQaBnI9J3f6yCVhiV5amBpYPMqwIemOVZ-xheU9Hte-wgDYTOctoD7bXfqwoHC_HhItmdsBDwlozdTPR5R0c6b8OAVUKyQ6LwaDIEjEyzQ2kW9kjIzRKkgfbn8ZY0oAPpwkOyBNxVhf_3n5rvezgZoku6wEHWXFPw_qlWV0jeF__Dre6YAIbRx4UrohW2Pu49O-GyiL-VsCPEIKMD_wL6nzYKvsRGR56F1V6LWZ5JDTPwzt38e2A5-m5Ht3vHaMI6D5M1X5YW8WaBfy-0CKlsoKwtbRsXjJk4fq6rbAVOKyNutHFrz5ny0gbDuxAddDYQC6gbL5PaYRXPd1au2GNetgCbNJwMgC3DQlPGb81SH_Ggd3gFsWNXMaPXBNnzH7VxOywnirUwJkCFNzIPKg5JkD8a69fnY3PWmgAp56_LlJ5MLErXb9eKrqJgA5CYp7C2iroCkOmjbfWThQ66VTXR8W6DJSWiyyB4J5xVJKJsVrw98J9l8qHzl051scqjV0aFHIrahJPlAO8NaUtIqN22Zvg2jIBVvJFYDfLYQihwA2atkPQvbTAQn-0y0Dbow9M4zFEJTGeoO6-AN5Ze8s5FHnJrXaAipI3oMS04gSHWUU7QwXYus1FAA2UDUgOsWDXkoiFo8kMabYajOWNh7M_7XDTszU4S0ejSM_3v45AouC4NpJ7wukdZcoZAPwwXhLDLbBrDZyBXALcowzXsM8MDJA4NcaGd9mx9wDeQuD2Loyg-e9WvM1Ady6GFmtlLu4LUlTJBdNOEU2rEXjTnqDB5ZQWPUQHK9l_4HuGpOzodcH-lWdiDT3LY-A4YodW1mu-heem370rOq8Aoj0xrE1KAjg505M9-lbg5Z8Vr7i4ieu8t_ipec73wHVJG_n7nWEADOF74-pBPzsyZB2Ib_uQz5U0WJorVdeah2byd9kBcsKr6w03xbIqljgB5oTnNhwADijt7CDb0x5ux2NaxEZVm0y0iTgCE0ZAC4f-ioLaGUWkuFOqRfUvfp4jri8lCnr_lNPveYY2_xmRpzHJLuhDKOncgmx1XnieQNiWdNTYaY-w-EAcPo9GtdAqR7OXZKaGlPGNtgvtubKtLZ4ah0a7UsZuwIIkOvSFg4--lCTj962oxdLkwIhGPvtHeDWLrcP4kqaasplKdAKBaSIqKKKYUYEDNyCfJ8xrGurb6MkM0E4hkYVX053zXYYIosRBIqtnWrM3y7622mKkMD4Tcifh8kvZ3d3_KgvFBta1mBJ-fwmxszdolJBUvbi3K-E3-OK_IdNH-kfjFLFDeL6Feuruu3zsK5eiSanbR6lUSk5wO5lCMOq4s3LnAomO5gEdM-aMJEMjjqH-W8uyZ4AM_eURjUHqP1xfO_oPAZELGAMkGuPfzDKxYA3Akw3RuN3_M_eBLK8oth_2P1RbHZxyuSdlXY9ig_-Yj1L6BQfQzFwD-JwNc8qrLd5cC08wPeghkhfG7uOIssAGjmntTHlcA8cxKjuqq4rThEavuNuWLEPthSFOZH1yWS7U369AhV-KnZQkumfpY0CjqLqKjqUO91H6nKNIOZx0giUeHIlSzjUvsomvCNs8wu0VAmH2IQD8K9kmh95xoNIr9hbeBhyBuBjEBjxBEyGh-KG-EmFNfM_bjqaimCnfCLupPdqSyW862ck2tnQ1V85DldcdxdmaueQJtiohr4hpOjBL7_cKDu0h5bZdepBeeMeIlJwKalPgV4ra4kPxOa7mbKpsfKYt-z97cGB0GAa8lqX9yiKsjzGzGe7-Nxd-JgW2f6w_EvXI2aqjL3GoOqtoGdGpdmQfA2DdtECI5GzuUMOLnMN7hvqTeYQQXG_vNzP0mjGNm4-7Ud1SR22tB11UoaYYrbyZYJW_fdsolWks-nAmezwZorJS5_a15a_AHAu5NamMWTWcR7nY55OD8HTu7p0HW7SY8YMQJLNj0x-DmJ5_ZM1q4VGMtLxlisLp03EIfMNMvvYOJdF7EDPRefnAF2780hvj68nneMu4BjtD-P-dL9CYb584fJC_mtjW8QF_7T4bEsahHsHkFARWVITOzFXK0_4xF1UZaUzonbPXKyBrgK4UjLJNlIlCLSVtWyeZGodzK8J7yh5sW1XgA3rEBZrKRezJKRFqofGzJayhEq5dbFvP7Jq6yM51xO_7SGQTCdD5FWEg8XE2k8oMgSs8EznyAh1C3WjoxaRPjCONtnVolwVqyG06-oDNZtBOo-PlRYwhGP2hRX-VR0r8kNhqlUihTR5vaNw9hJc7vuD2EuftkRRsO2VbxbkVPFu6Ys3N5iwSYA5eUqdonsDpqKW2igqrKIT1tdHcTm3a0R-nKtOu3GS4POJJ4G0556nlh9b6TGKYCpkpqRZBOYBrzKknOolDqZ-5jKjHi3xTlET7WrjmJs8HkBVSgaDuh65u4kyybG2ZLhjTiBGEjGGFzkqexP4uK79c3OC46Vx5jVNMQAd8avnSyKk5sfbZuY6f8K3_SMFUcDzKiPj-yAeRjZuvtUKnTKkuG8MvFmNsMVYxv9tHaE57xdeoOR4ADe6uCxI8K6yeOLBcMw-0Sim6bQt7GF3-4I-bwwSRWsKnPYdMPvqpKEXxQ-P3jIgQTmr_Q3I6zsxJXw5ZF6IbMExidGWItPvg8JGaFXEKaiAcplXrhWOBZYX5ZrXhzXQeRrH0FLdo-jU9gjM24mHl"
        val key = KeyCreator().setPrivateKey(mKeyPem).setPassword(password).createEncryptionKey()

        // Decrypt
        val decryptedMessage = key.decryptBase64(data, Base64Option.URL)

        Assert.assertNotEquals(decryptedMessage.length, 0)
    }
}