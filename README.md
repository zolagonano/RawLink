# RawLink

RawLink is a fast, encrypted TCP tunnel written in Rust.

**NOTE:** The code was written with the assistance of AI, and I have thoroughly reviewed it. However, it still needs a more thorough and in-depth security audit. Use it at your own risk, and apply appropriate security measures when using it for sensitive work.


## Features

- Encrypted connections using AES-256-GCM.
- One connection can carry many streams.
- Optional traffic obfuscation to make the connection harder to recognize.
- Optional SSH traffic mimicry.
- Automatically reconnects when a tunnel fails.
- Supports multiple tunnels.
- Uses a pre-shared key to authenticate connections.

## How It Works

RawLink takes traffic from a local SOCKS5 proxy, encrypts it, and sends it through a tunnel to the remote server. The server decrypts the data and forwards it to its destination. Multiple connections can share the same tunnel.

### Packet Format

RawLink encrypts data using AES-256-GCM (support for other encryption schemes can be added in the future) and adds information such as a session ID and packet number. When using TCP, each packet also has a length prefix so the receiver can identify where it ends.

```text
 byte 0        bytes 1..9              bytes 9..17          bytes 17..
+-------+-----------+-----------------+----------------+------------------+
|ver|kp|r| session id (u64, LE)       | packet number  | encrypted body   |
| 4|1|3 |       8 bytes               | (u64, LE)      | + 16-byte tag    |
+-------+-----------+-----------------+----------------+------------------+
 \______ ___________/                   \______ _______/
        v                                      v
   17-byte header (AAD)                    AES-256-GCM
```

The header is not encrypted because the receiver must read the session id and packet number *before* it can look up the key to decrypt the body. To fix this issue every 17-byte header is **XOR-masked with an XChaCha20 keystream** before it goes on the wire. After this, the entire packet shoud appear as uniform random to anyone without the PSK

### Obfuscation Layer

The optional obfuscation layer modifies how traffic looks on the network, making it harder to recognize as RawLink traffic. It can also use optional SSH traffic mimicry. The layer is separate from the core protocol.

For now it has two optional obfuscation modes to make its traffic harder to recognize:

- rand: Makes traffic look like random data. It masks packet headers, adds random padding, and can send dummy traffic during idle periods.

- ssh: Makes the connection look like an SSH session, including the initial handshake, before switching to encrypted tunnel traffic.

## How to Use

```
# server
rawlink server --listen 0.0.0.0:6123 \
    --psk <64-hex-chars>

# client
rawlink client --server <server-ip>:6123 \
    --socks-listen 127.0.0.1:1080 \
    --psk <64-hex-chars>

# use it
curl --proxy socks5h://127.0.0.1:1080 https://example.com
```

With SSH obfuscation:

```
# server: SSH camouflage, makes it looks like an ordinary sshd
target/release/rawlink server --listen 0.0.0.0:6123 --psk <64-hex> \
    --obfs ssh --ssh-banner 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5'

# client (banners must mach)
target/release/rawlink client --server <server-ip>:6123 \
    --socks-listen 127.0.0.1:1080 --psk <64-hex> --obfs ssh
```

With random noise obfuscation:

```
# server
target/release/rawlink server --listen 0.0.0.0:6123 --psk <64-hex> --obfs rand

# client (must match the server's mode)
target/release/rawlink client --server <server-ip>:6123 \
    --socks-listen 127.0.0.1:1080 --psk <64-hex> --obfs rand
```


## Documentation

**NOTE:** The protocol documentation and specifications are currently a work in progress.

## Status

RawLink is under development. Its security and resistance to network censorship have not yet been verified. I appreciate all feedback on this project, so feel free to open issues and submit PRs.

## Support

If you would like to support the development of this project, you can do so here:

[https://zola.ink/support](https://zola.ink/support)

## License

Under the MIT or Apache-2.0 license.
