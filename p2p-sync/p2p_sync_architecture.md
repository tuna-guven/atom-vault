# P2P Sync Architecture: The Briar Protocol Stack

This document outlines the architecture of our vault's peer-to-peer (P2P) synchronization engine. The design draws heavy inspiration from the **Briar Protocol**, utilizing Tor hidden services, perfect forward secrecy, and stream multiplexing to ensure completely anonymous, metadata-free, and secure data exchange.

---

## 1. Identity & Addressing (The Daily Key System)

Unlike standard web protocols where IP addresses define location, our vault operates entirely over the Tor network to obscure physical locations. Routing is handled via cryptographic identities.

### Long-Term Identity (Ed25519)
Every vault generates a master long-term `Ed25519` keypair upon creation. The public key acts as the vault's permanent identity. When you share a vault link with a friend, you are exchanging these public keys and a 32-byte shared **Master Secret**.

### The Daily Address (Unlinkability)
If vaults always connected to the same `.onion` address, an adversary monitoring the Tor network could correlate connectivity times and build a metadata graph of your communication. 

To prevent this, we use the Briar Protocol's **Daily Key** concept:
1. Every 24 hours, the vault takes the long-term public keys of both peers, the current date (in days since the Unix epoch), and the shared Master Secret.
2. It hashes these together using HKDF (HMAC-based Extract-and-Expand Key Derivation Function) to produce a temporary, single-use `Ed25519` keypair.
3. This temporary key generates today's `.onion` V3 address.

Because both peers know the Master Secret, they can independently calculate each other's `.onion` address for any given day. To an outside observer, the addresses change entirely every 24 hours, guaranteeing **cryptographic unlinkability**.

---

## 2. The Transport Layer (Tor & Arti)

To establish the connection, the vault relies on the Tor network. 

* **The Listener (Bob):** Hosts a Tor Onion Service bound to a local TCP port. The Tor network routes traffic to this port securely.
* **The Dialer (Alice):** Uses the `arti-client` (an embedded Rust Tor client) to download the global Tor consensus, build a 3-hop circuit, and resolve the daily `.onion` address. 

By embedding Arti directly into the vault binary, we remove the need for external proxies and guarantee that all traffic stays strictly within the Tor overlay network (bypassing NAT issues and local firewalls).

---

## 3. Cryptographic Handshake (Noise_XX)

Once a raw Tor TCP connection is established, the peers must authenticate each other and encrypt the session. We use the **Noise Protocol Framework**, specifically the `Noise_XX_25519_ChaChaPoly_BLAKE2s` pattern.

### How Perfect Forward Secrecy (PFS) is Achieved
1. **Ephemeral Key Generation:** When Alice connects to Bob, both immediately generate brand new, single-use `X25519` keypairs (ephemeral keys).
2. **Diffie-Hellman Exchange:** They exchange public ephemeral keys and perform an Elliptic-Curve Diffie-Hellman (ECDH) operation to derive a shared session key.
3. **Identity Verification:** Using the new encrypted channel, they transmit signatures of their long-term `Ed25519` keys to prove they are the true owners of the vault.
4. **Session Key Destruction:** Once the session ends, the ephemeral keys are permanently deleted from RAM.

**The PFS Guarantee:** If an adversary records your Tor traffic today, and somehow steals your vault's master private key tomorrow, they **cannot decrypt the past traffic**. The session keys used to encrypt the data were ephemeral and destroyed, providing true forward secrecy.

---

## 4. Multiplexing (Yamux)

Tor streams and Noise encryptions are "single-pipe" protocols. However, efficient Merkle-tree vault synchronization requires concurrently sending block requests, fetching data, and exchanging vault state. 

We wrap the encrypted Noise stream in **Yamux** (Yet Another Multiplexer). 

* Yamux takes the single encrypted TCP pipe and splits it into hundreds of lightweight, concurrent sub-streams.
* It handles flow control, ensuring large file transfers do not choke out smaller status messages.
* Because the multiplexer sits *inside* the Noise encryption tunnel, the Tor network only sees a uniform stream of random encrypted bytes, hiding the fact that multiple files are syncing simultaneously.
