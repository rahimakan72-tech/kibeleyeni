package com.kibele.securekeys

import java.security.Signature

object Signer {
    fun sign(data: ByteArray): ByteArray {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(KeyManager.getPrivate(KeyManager.ALIAS_ID_SIG))
        sig.update(data)
        return sig.sign()
    }
    fun verify(data: ByteArray, signature: ByteArray): Boolean {
        return try {
            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(KeyManager.getPublic(KeyManager.ALIAS_ID_SIG))
            sig.update(data)
            sig.verify(signature)
        } catch (_: Exception) { false }
    }
}
