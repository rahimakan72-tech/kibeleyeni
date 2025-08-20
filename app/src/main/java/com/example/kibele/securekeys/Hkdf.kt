package com.kibele.securekeys

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF (RFC 5869) – HMAC-SHA256
 */
object Hkdf {
    /**
     * @param key  IKM (input keying material)
     * @param salt Opsiyonel (null ise zero-salt)
     * @param info Context bilgisi
     * @param len  Çıkış anahtar uzunluğu (bayt)
     */
    fun derive(key: ByteArray, salt: ByteArray?, info: ByteArray, len: Int = 32): ByteArray {
        val prk = hmacSha256(salt ?: ByteArray(32) { 0 }, key)
        val out = ByteArray(len)
        var t = ByteArray(0)
        var pos = 0
        var i = 1
        while (pos < len) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            mac.update(t)
            mac.update(info)
            mac.update(i.toByte())
            t = mac.doFinal()
            val toCopy = minOf(t.size, len - pos)
            System.arraycopy(t, 0, out, pos, toCopy)
            pos += toCopy
            i++
        }
        // Temizlik
        t.fill(0)
        return out
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}
