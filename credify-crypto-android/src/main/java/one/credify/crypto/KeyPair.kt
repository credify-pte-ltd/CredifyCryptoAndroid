package one.credify.crypto

internal abstract class KeyPair<PI, PU> {
    protected var mPrivateKey: PI? = null
    protected var mPublicKey: PU? = null
}