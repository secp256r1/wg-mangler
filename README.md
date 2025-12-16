# wg-mangler

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Usage](#usage)
  - [1. Generate Key](#1-generate-key)
  - [2. Run the Server](#2-run-the-server)
  - [3. Run the Client](#3-run-the-client)
- [Acknowledgements](#acknowledgements)
- [Similar Tools](#similar-tools)

## Overview

`wg-mangler` is a lightweight and efficient tool designed to obfuscate WireGuard VPN traffic. It acts as a simple proxy that mangles the headers of WireGuard messages, helping to disguise the traffic from deep packet inspection (DPI).

Its simplicity is a key feature: it requires no `tun` devices and no `nftables` or `iptables` rules. It's built to be resource-friendly, making it ideal for low-power devices, including routers running OpenWrt. Because it only performs a minor XOR transformation on the message headers, the computational overhead is minimal.

## Features

- **Lightweight Obfuscation:** Hides WireGuard traffic with minimal performance impact.
- **No Payload Overhead:** WireGuard's MTU remains unchanged as `wg-mangler` doesn't add to the payload size.
- **Simple to Use:** No complex setup, `tun` devices, or firewall rules needed.
- **Low Resource Usage:** Small memory and CPU footprint.
- **OpenWrt Support:** Works great on embedded Linux devices.
- **Minimal Latency:** Fast header-only transformation adds negligible delay.

## How It Works

`wg-mangler` runs as a client on your local machine and a server on your VPS, wrapping your existing WireGuard connection.

```text
+-------------------+      +--------------------+      +--------------------+      +-----------------+
| Local WireGuard   | <--> | wg-mangler client  | <--> | wg-mangler server  | <--> |  VPS WireGuard  |
| (e.g. 127.0.0.1)  |      | (e.g. 127.0.0.1)   |      | (Your VPS public IP) |      | (e.g. 127.0.0.1)|
+-------------------+      +--------------------+      +--------------------+      +-----------------+
```

## Usage

The setup involves three steps: generating a shared secret key, running the server on your remote machine (VPS), and running the client on your local machine.

### 1. Generate Key

First, generate a secret key that will be shared between the client and server. Run the following command and save the output to a file.

```sh
wg-mangler generate-key
```

### 2. Run the Server

On your VPS, run `wg-mangler` in **server** mode. It will listen for incoming traffic from your client and forward the decoded packets to your WireGuard server instance.

- `--listen` (`-l`): The public-facing IP and port to listen for client connections (e.g., `0.0.0.0:12345`).
- `--forward` (`-f`): The address and port where your WireGuard server is running (e.g., `127.0.0.1:51820`).
- `--key` (`-k`): The secret key.

```sh
# On your VPS
wg-mangler server --listen 0.0.0.0:12345 --forward 127.0.0.1:51820 --key key
```

### 3. Run the Client

On your local machine, run `wg-mangler` in **client** mode. This will create a local listener for your WireGuard client to connect to. It will encode packets and send them to your `wg-mangler` server.

- `--listen` (`-l`): The local IP and port for your WireGuard client to connect to (e.g., `127.0.0.1:15820`).
- `--forward` (`-f`): The public IP and port of your `wg-mangler` server (e.g., `YOUR_VPS_IP:12345`).
- `--key` (`-k`): The secret key.

```sh
# On your local machine
wg-mangler client --listen 127.0.0.1:15820 --forward YOUR_VPS_IP:12345 --key key
```

Finally, update your local WireGuard client configuration to use the `wg-mangler` client address as its endpoint:

**Original WireGuard Config:**
```
[Peer]
Endpoint = YOUR_VPS_IP:51820
...
```

**New WireGuard Config:**
```
[Peer]
Endpoint = 127.0.0.1:15820
...
```

Now your WireGuard traffic will be seamlessly obfuscated through `wg-mangler`.

## Acknowledgements

- **Gemini:** For assisting with a significant portion of the coding work.
- **[phantun](https://github.com/dndx/phantun)**: A long-term tool used before `wg-mangler`.
- **[udp2raw](https://github.com/wangyu-/udp2raw)**: Another long-term tool used before `wg-mangler`.

## Similar Tools

- **[wg-obfuscator](https://github.com/ClusterM/wg-obfuscator)**
