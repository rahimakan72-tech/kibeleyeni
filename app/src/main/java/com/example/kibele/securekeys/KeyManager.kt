package com.kibele.securekeys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec

object KeyManager {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    const val ALIAS_ID_SIG = "kbl_id_sig_v1"
    const val ALIAS_ID_KEX = "kbl_id_kex_v1"

    fun ensureIdentityKeys(): Pair<PublicKey, PublicKey> {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!ks.containsAlias(ALIAS_ID_SIG)) generateSigningKey()
        if (!ks.containsAlias(ALIAS_ID_KEX)) generateKexKey()
        val sigPub = ks.getCertificate(ALIAS_ID_SIG).publicKey
        val kexPub = ks.getCertificate(ALIAS_ID_KEX).publicKey
        return sigPub to kexPub
    }

    private fun baseBuilder(alias: String, purposes: Int): KeyGenParameterSpec.Builder {
        val b = KeyGenParameterSpec.Builder(alias, purposes)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                30,
                BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .setUnlockedDeviceRequired(true)
        try { b.setIsStrongBoxBacked(true) } catch (_: Throwable) { }
        return b
    }

    private fun generateSigningKey() {
        // Prefer ECDSA-P256 for broad compatibility (Ed25519 not widely supported via Keystore)
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val spec = baseBuilder(ALIAS_ID_SIG, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .build()
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }

    private fun generateKexKey() {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        val spec = baseBuilder(ALIAS_ID_KEX, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .build()
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }

    fun getPrivate(alias: String): PrivateKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.getKey(alias, null) as PrivateKey
    }
    fun getPublic(alias: String): PublicKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.getCertificate(alias).publicKey
    }
    fun isHardwareBacked(alias: String): Boolean {
        val priv = getPrivate(alias)
        val kf = KeyFactory.getInstance(priv.algorithm, ANDROID_KEYSTORE)
        val info = kf.getKeySpec(priv, KeyInfo::class.java)
        return info.isInsideSecureHardware
    }
}
