package com.kibele.securekeys

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * KBL1 zarfı: ECDH-P256 + HKDF-SHA256 + AES-256-GCM (DEK + KEK)
 */
object CryptoBox {
    private const val MAGIC = 0x4B_42_4C          // 'KBL'
    private const val VER: Byte = 0x01
    private const val ALG_ECDH_AEG: Int = 0xA1    // Int; yazarken/okurken .toByte()

    private val rnd = SecureRandom()

    /** Alıcının KEX açık anahtarı (DER) ile şifreler. */
    fun encrypt(recipientKexPubDer: ByteArray, plaintext: ByteArray): ByteArray {
        // 1) Ephemeral EC-P256
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val eph = kpg.generateKeyPair()
        val ephPubDer = eph.public.encoded

        // 2) ECDH
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(eph.private)
        val recipientPub: PublicKey =
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(recipientKexPubDer))
        ka.doPhase(recipientPub, true)
        val shared = ka.generateSecret()

        // 3) HKDF
        val salt = ByteArray(16).also { rnd.nextBytes(it) }
        val info = ByteBuffer.allocate(ephPubDer.size + recipientKexPubDer.size)
            .put(ephPubDer).put(recipientKexPubDer).array()
        val okm = Hkdf.derive(shared, salt, info, 64)
        val kek = okm.copyOfRange(0, 32)   // KEK: DEK’i sarmak için
        val dek = okm.copyOfRange(32, 64)  // veri anahtarı

        // 4) Veri şifrele (DEK)
        val nonceData = ByteArray(12).also { rnd.nextBytes(it) }
        val ct = aesGcmEncrypt(dek, nonceData, plaintext)

        // 5) DEK sarmala (KEK)
        val nonceWrap = ByteArray(12).also { rnd.nextBytes(it) }
        val wrappedDek = aesGcmEncrypt(kek, nonceWrap, dek)

        // 6) Serileştir
        val bb = ByteBuffer.allocate(
            4 + 1 + 1 +
                    2 + ephPubDer.size +
                    2 + salt.size +
                    2 + nonceData.size +
                    4 + ct.size +
                    2 + nonceWrap.size +
                    4 + wrappedDek.size
        )
        bb.putInt(MAGIC)
            .put(VER)
            .put(ALG_ECDH_AEG.toByte())
            .putShort(ephPubDer.size.toShort()).put(ephPubDer)
            .putShort(salt.size.toShort()).put(salt)
            .putShort(nonceData.size.toShort()).put(nonceData)
            .putInt(ct.size).put(ct)
            .putShort(nonceWrap.size.toShort()).put(nonceWrap)
            .putInt(wrappedDek.size).put(wrappedDek)

        // Temizlik
        shared.fill(0); okm.fill(0); dek.fill(0)

        return bb.array()
    }

    /** Keystore’daki ECDH private anahtarıyla çözer. */
    fun decryptWithKeystore(recipientAliasKex: String, blob: ByteArray): ByteArray {
        val priv: PrivateKey = KeyManager.getPrivate(recipientAliasKex)
        return decrypt(priv, blob)
    }

    /** Verilen ECDH private anahtarla çözer. */
    fun decrypt(privateKey: PrivateKey, blob: ByteArray): ByteArray {
        val bb = ByteBuffer.wrap(blob)

        fun readU16(): Int = bb.short.toInt() and 0xFFFF
        fun readBytesU16(): ByteArray { val n = readU16(); return ByteArray(n).also { bb.get(it) } }
        fun readBytesU32(): ByteArray { val n = bb.int; return ByteArray(n).also { bb.get(it) } }

        require(bb.int == MAGIC) { "bad magic" }
        require(bb.get() == VER) { "bad ver" }
        require(bb.get() == ALG_ECDH_AEG.toByte()) { "bad alg" }

        val ephPubDer = readBytesU16()
        val salt = readBytesU16()
        val nonceData = readBytesU16()
        val ct = readBytesU32()
        val nonceWrap = readBytesU16()
        val wrappedDek = readBytesU32()

        // ECDH
        val ephPub: PublicKey =
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(ephPubDer))
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(privateKey)
        ka.doPhase(ephPub, true)
        val shared = ka.generateSecret()

        // HKDF
        val selfPubDer = encodePublicKeyToDer(KeyManager.getPublic(KeyManager.ALIAS_ID_KEX))
        val info = ByteBuffer.allocate(ephPubDer.size + selfPubDer.size)
            .put(ephPubDer).put(selfPubDer).array()
        val okm = Hkdf.derive(shared, salt, info, 64)
        val kek = okm.copyOfRange(0, 32)
        val dek = aesGcmDecrypt(kek, nonceWrap, wrappedDek)

        // Veri çöz
        val pt = aesGcmDecrypt(dek, nonceData, ct)

        // Temizlik
        shared.fill(0); okm.fill(0); dek.fill(0)

        return pt
    }

    // ---- Eklenen yardımcı ----
    fun encodePublicKeyToDer(pub: PublicKey): ByteArray =
        KeyFactory.getInstance("EC")
            .getKeySpec(pub, X509EncodedKeySpec::class.java)
            .encoded

    // ---- AES-GCM yardımcıları ----
    private fun aesGcmEncrypt(key: ByteArray, nonce: ByteArray, pt: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return c.doFinal(pt)
    }
    private fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, ct: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        return c.doFinal(ct)
    }
}
