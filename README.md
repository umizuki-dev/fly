# fly - Minimalist VPNGate Client

`fly` is a high-performance, secure, and minimalist command-line VPN client for VPNGate. Designed for speed and simplicity, it can establish a connection in under 5 seconds.

## Features

- **Ultra-Fast:** Parallel server probing and local latency testing to find the fastest connection.
- **Secure:** VPN configurations are piped directly to OpenVPN via `stdin`, ensuring sensitive data never touches the disk.
- **Minimalist:** A clean, flag-driven CLI with a silent "dashboard" interface.
- **Robust:** Built-in signal handling for graceful disconnection and automatic cleanup.
- **Performance-Oriented:** Optimized C++ code with a sub-second server verification phase.

## Installation

### Prerequisites

- `g++` (C++17 support)
- `libcurl`
- `openvpn`
- `sudo` privileges (required for OpenVPN to manage network interfaces)

### Build and Install

```bash
make
sudo make install
```

## Usage

```bash
fly --help
```

### Examples

- **Auto-connect to the best Japanese server:**
  ```bash
  fly -a
  ```

- **Connect to a server in a specific country (e.g., US):**
  ```bash
  fly -c US
  ```

- **List servers with a specific protocol (e.g., TCP):**
  ```bash
  fly -p tcp
  ```

- **Disconnect any active session:**
  ```bash
  fly -k
  ```

## Performance Note

In `--auto` mode, `fly` uses an "Early GO" logic. As soon as it finds a server with very low latency (< 35ms), it triggers the connection immediately without waiting for other probes to finish.

## License

MIT License. See `LICENSE` for details.
