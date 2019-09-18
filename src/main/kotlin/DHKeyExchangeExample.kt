package io.ryter.backend

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement
import javax.crypto.interfaces.DHPublicKey

class DHExchangePartner(private val name: String) {

    private lateinit var keyAgreement: KeyAgreement

    private fun createPersonalDHKeypairAndInitAgreement(initKeyPairGenerator: (KeyPairGenerator) -> Unit): KeyPair {
        println("$name: Generating DH keypair")
        val keyPair = KeyPairGenerator.getInstance("DH").apply {
            initKeyPairGenerator(this)
        }.generateKeyPair()
        initializeKeyAgreement(keyPair)
        return keyPair
    }

    fun createPersonalDHKeypairAndInitAgreement(bitSize: Int = 4096): KeyPair =
        createPersonalDHKeypairAndInitAgreement { it.initialize(bitSize) }

    fun createPersonalDHKeypairAndInitAgreement(publicKey: DHPublicKey): KeyPair =
        createPersonalDHKeypairAndInitAgreement { it.initialize(publicKey.params) }

    fun createPublicKeyFromEncodedMaterial(encoded: ByteArray): DHPublicKey {
        println("$name: Instantiating DH public key from encoded key material.")
        val keyFactory = KeyFactory.getInstance("DH")
        return keyFactory.generatePublic(X509EncodedKeySpec(encoded)) as DHPublicKey
    }

    private fun initializeKeyAgreement(keyPair: KeyPair) {
        println("$name: Initialization ...")
        keyAgreement = KeyAgreement.getInstance("DH").apply {
            init(keyPair.private)
        }
    }

    fun phaseOne(partnerPublicKey: DHPublicKey) {
        println("$name: Execute PHASE1 ...")
        keyAgreement.doPhase(partnerPublicKey, true)
    }

    fun generateSharedSecret(): ByteArray = keyAgreement.generateSecret()

}

fun main() {

    //Alice creates her own DH key pair with 2048-bit key size
    val alice = DHExchangePartner("Alice")
    val aliceKpair = alice.createPersonalDHKeypairAndInitAgreement(4096)

    // Alice encodes her public key, and sends it over to Bob.
    val alicePubKeyEnc: ByteArray = aliceKpair.public.encoded

    /**
    _______ SENDING OVER TO BOB
     */
    /*
     * Bob has received Alice's public key in encoded format.
     * He instantiates a DH public key from the encoded key material.
     */
    val bob = DHExchangePartner("Bob")

    val alicePubKeyForBob = bob.createPublicKeyFromEncodedMaterial(alicePubKeyEnc)

    // Bob creates his own DH key pair using alice's parameters
    val bobKpair = bob.createPersonalDHKeypairAndInitAgreement(alicePubKeyForBob)

    // Bob encodes his public key, and sends it over to Alice.
    val bobPubKeyEnc = bobKpair.public.encoded

    // Bob uses Alice's public key for the first (and only) phase of his version of the DH protocol.
    bob.phaseOne(alicePubKeyForBob)

    /**
    _______ SENDING OVER TO ALICE
     */

    //Alice instantiates a DH public key from Bob's encoded key material.
    val bobPubKeyForAlice = alice.createPublicKeyFromEncodedMaterial(bobPubKeyEnc)
    //Alice uses Bob's public key for the first (and only) phase of her version of the DH protocol.
    alice.phaseOne(bobPubKeyForAlice)

    /**
    _______ At this stage, both Alice and Bob have completed the DH key agreement protocol. Both generate the (same) shared secret.
     */

    val aliceSharedSecret = alice.generateSharedSecret()
    println(aliceSharedSecret.asHex())
    val bobSharedSecret = bob.generateSharedSecret()
    println(bobSharedSecret.asHex())

    require(aliceSharedSecret.contentEquals(bobSharedSecret))

}

private fun ByteArray.asHex() = joinToString("") { "%02x".format(it) }