package com.example.kibele.securekeys

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.kibele.securekeys.CryptoBox
import com.kibele.securekeys.KeyManager

enum class CryptoMode { AES_LOCAL, KBL1 }

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            var plain by remember { mutableStateOf("") }
            var cipherText by remember { mutableStateOf("") }
            var decrypted by remember { mutableStateOf("") }
            var mode by remember { mutableStateOf(CryptoMode.AES_LOCAL) }
            var recipientKexPubB64 by remember { mutableStateOf("") }

            // ✅ düz remember → String
            val myKexPubDer = remember {
                KeyManager.ensureIdentityKeys()
                val der = CryptoBox.encodePublicKeyToDer(KeyManager.getPublic(KeyManager.ALIAS_ID_KEX))
                android.util.Base64.encodeToString(der, android.util.Base64.NO_WRAP)
            }

            Column(Modifier.padding(16.dp)) {
                Text("Kibele Secure", style = MaterialTheme.typography.headlineSmall)

                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value = plain, onValueChange = { plain = it },
                    label = { Text("Plaintext") },
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(Modifier.height(12.dp))
                Button(onClick = {
                    cipherText = when (mode) {
                        CryptoMode.AES_LOCAL -> {
                            android.util.Base64.encodeToString(
                                plain.encodeToByteArray(), android.util.Base64.NO_WRAP
                            )
                        }
                        CryptoMode.KBL1 -> {
                            val der = android.util.Base64.decode(
                                if (recipientKexPubB64.isEmpty()) myKexPubDer else recipientKexPubB64,
                                android.util.Base64.NO_WRAP
                            )
                            val ct = CryptoBox.encrypt(der, plain.encodeToByteArray())
                            android.util.Base64.encodeToString(ct, android.util.Base64.NO_WRAP)
                        }
                    }
                }) { Text("Encrypt") }

                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = cipherText, onValueChange = { cipherText = it },
                    label = { Text("Ciphertext (B64)") },
                    modifier = Modifier.fillMaxWidth()
                )

                Spacer(Modifier.height(12.dp))
                Button(onClick = {
                    decrypted = when (mode) {
                        CryptoMode.AES_LOCAL -> {
                            val bytes = android.util.Base64.decode(cipherText, android.util.Base64.NO_WRAP)
                            bytes.decodeToString()
                        }
                        CryptoMode.KBL1 -> {
                            val bytes = android.util.Base64.decode(cipherText, android.util.Base64.NO_WRAP)
                            CryptoBox.decryptWithKeystore(KeyManager.ALIAS_ID_KEX, bytes).decodeToString()
                        }
                    }
                }) { Text("Decrypt") }

                Spacer(Modifier.height(8.dp))
                Text("Decrypted: $decrypted")

                Spacer(Modifier.height(16.dp))
                Text("My KEX Public (B64):")
                Text(myKexPubDer)

                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    value = recipientKexPubB64, onValueChange = { recipientKexPubB64 = it },
                    label = { Text("Recipient KEX Public (B64)") },
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }
    }
}
