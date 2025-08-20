package com.kibele.securekeys

import java.security.KeyStore

object Attestation {
    data class AttestInfo(val alias: String, val hardwareBacked: Boolean, val certCount: Int)

    fun get(alias: String): AttestInfo {
        val hw = KeyManager.isHardwareBacked(alias)
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val chain = ks.getCertificateChain(alias)?.toList() ?: emptyList()
        return AttestInfo(alias, hw, chain.size)
    }
}
