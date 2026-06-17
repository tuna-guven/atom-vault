# Vault P2P Sync Testing Guide (secureblue / Distrobox)

This guide walks you through testing the p2p-sync transport layer on secureblue. We will run two tests: a fast local loopback test, and a full live test over the global Tor network.

---

## Prerequisites: Distrobox

Create and enter your Distrobox environment:

```bash
distrobox create -n tor-test --image ghcr.io/ublue-os/fedora-toolbox:latest
distrobox enter tor-test
```

*Note: Run your Tor daemon commands inside this Distrobox. Run your cargo commands on your normal host terminal (outside Distrobox).*

---

## Test 1: Local Loopback Test

This test bypasses Tor entirely and connects Alice to Bob over 127.0.0.1. It mathematically proves the Noise_XX encryption and Yamux multiplexing are functioning correctly.

1. Open a terminal on your host machine (outside Distrobox) in the p2p-sync directory.
2. Run the test suite:

```bash
cargo test --test loopback
```

3. You should see a clean ok result indicating the handshake and multiplexed data transfer succeeded.

---

## Test 2: Live Tor Network Test

This test connects two standalone vault binaries across the live internet via the Tor network, exactly how the production app will function.

### Step 1: Start Bob's Tor Hidden Service

We need to spin up a Tor daemon to host Bob's listener. Inside your **Distrobox terminal**, run:

```bash
sudo dnf install -y tor

mkdir -p /tmp/tor_test/data
chmod 700 /tmp/tor_test/data/

cat << EOF > /tmp/tor_test/torrc
HiddenServiceDir /tmp/tor_test/data/
HiddenServicePort 80 127.0.0.1:8080
EOF

tor -f /tmp/tor_test/torrc &
```

Wait about 15 seconds for Tor to bootstrap to 100%. Then, print Bob's newly generated .onion address:

```bash
cat /tmp/tor_test/data/hostname
```

**Copy this address.**

### Step 2: Configure Alice (The Dialer)

1. Open src/bin/alice.rs in your code editor (on your host machine).
2. Locate the line defining onion_addr (around line 14).
3. Paste the .onion address you copied from Bob.

```rust
let onion_addr = "your_actual_address_here.onion";
```

4. Save the file.

### Step 3: Run the Listener (Bob)

Open a new terminal on your **host machine** (outside Distrobox), navigate to p2p-sync, and start Bob.

```bash
cargo run --bin bob
```

Bob will bind to **127.0.0.1:8080** and wait. The Tor daemon running inside your Distrobox is now forwarding traffic to this port.

### Step 4: Run the Dialer (Alice)

Open a second terminal on your **host machine** and start Alice.

```bash
cargo run --bin alice
```

### Expected Behavior

1. Alice will spend ~10 seconds bootstrapping the embedded arti-client onto the Tor network.
2. Alice will dial Bob's .onion address, routing traffic through Tor guard, relay, and rendezvous nodes.
3. Once connected, they will immediately execute the Noise_XX cryptographic handshake.
4. Finally, Yamux will open a stream and Alice will send a message. Bob will reply.
5. Both terminals will print Test complete.
