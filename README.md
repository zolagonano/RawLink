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

1. Run the RawLink server on a remote machine.
2. Run the RawLink client on your machine.
3. Configure your browser or application to use the local SOCKS5 proxy.
4. Your traffic travels through the encrypted tunnel to the server.

## Documentation

**NOTE:** The protocol documentation and specifications are currently a work in progress.

## Status

RawLink is under development. Its security and resistance to network censorship have not yet been verified. I appreciate all feedback on this project, so feel free to open issues and submit PRs.

## License

Under the MIT or Apache-2.0 license.
