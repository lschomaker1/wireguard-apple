# Obfuscation

Some networks block WireGuard outright. A raw WireGuard datagram is trivially
fingerprintable — the first byte is a message type (`1`…`4`) followed by three
zero "reserved" bytes, and the handshake messages have fixed, well-known
lengths — so a deep-packet-inspection box can match it and drop the flow.

This app can carry WireGuard over TCP instead, which removes the recognisable
UDP signature entirely. On the wire there is no WireGuard-shaped traffic at all,
just a TCP conversation with a web port.

## Turning it on

Add one line to the `[Interface]` section of a tunnel:

```ini
[Interface]
PrivateKey = …
Address    = 10.71.208.226/32
DNS        = 100.64.0.63
Obfuscation = udp2tcp:443

[Peer]
PublicKey  = …
Endpoint   = 185.209.196.75:51820      # leave this as the real endpoint
AllowedIPs = 0.0.0.0/0, ::/0
```

`udp2tcp:443` means "carry this tunnel over TCP port 443 on the peer's host".
`udp2tcp` on its own defaults to port 443. Leave `Endpoint` pointing at the real
server: the app rewrites it internally, so the tunnel keeps working normally if
you later remove the `Obfuscation` line.

If the tunnel has no `MTU` set, obfuscated tunnels get `MTU = 1280`.

## Which servers this works with

The encapsulation is Mullvad's `udp-over-tcp`, and **Mullvad's WireGuard servers
accept it directly on TCP ports 80, 443 and 5001**. That is the whole point: the
far end de-encapsulates it, so no server or VPS of your own is involved. Any of
those three ports works — 443 blends in best.

For a server you host yourself, run something that speaks the same framing in
front of it, e.g. [`udp-over-tcp`](https://github.com/mullvad/udp-over-tcp) or
`lwo server --transport udp2tcp`.

## How it works

```
  WireGuard  ──udp──►  loopback proxy  ──tcp/443──►  server
  (unchanged)          (this app)                   (de-encapsulates)
```

`ObfuscationProxy` listens on a loopback UDP port and the peer's `Endpoint` is
rewritten to point at it. Every datagram WireGuard sends is written to a TCP
connection behind a 2-byte big-endian length prefix; every frame read back is
handed to WireGuard as a datagram. WireGuard itself is untouched — it simply
talks to `127.0.0.1`.

The proxy's TCP connection is bound to the physical interface, the same way
relayed split-tunnel flows are. Without that, a full-tunnel config owns the
default route and the connection carrying the tunnel would be routed into the
tunnel it carries.

There is deliberately no encryption or masking in this layer: the far end is a
stock WireGuard server that would reject altered bytes, and the payload is
already encrypted and authenticated by WireGuard underneath.

## Trade-offs

- **It is obfuscation, not extra security.** Confidentiality and authenticity
  come entirely from WireGuard. This only changes what the traffic looks like.
- **TCP-over-TCP.** The tunnelled traffic is usually TCP as well, and stacking
  retransmission timers degrades badly under loss. Use it where UDP is blocked,
  not by default.
- **It defeats cheap, signature-based DPI**, which is what blocks WireGuard in
  practice. It is not a defence against active probing or long-run statistical
  traffic analysis.

## Checking it works

`Obfuscation` is parsed and re-serialised like any other field, so an invalid
value is reported when the config is saved rather than at connect time.

To confirm a path carries WireGuard before switching a device over, the
[`lwo`](https://github.com/lschomaker1/lwo) CLI can complete a real handshake
over it without touching the system VPN:

```sh
lwo verify --config mullvad.conf --via udp2tcp --port 443
```
