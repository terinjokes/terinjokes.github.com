---
layout: post
title: TLS with Erlang
categories:
- blog
---

Recently I configured an HTTP server written in Erlang for secure communication with TLS. When I through I was done, however, I was unable to connect without errors from command line tools or web browsers.

Undeterred, I dug into the HTTP server and Erlang's SSL library.

## Bundling Intermediate Certificates

If you spring for a cheap SSL certificate, you're likely to also get an intermediate certificate that bridges the trust from the Certificate Authorities trusted by the user-agent to the certificate for your site. If you don't provide the bundle, users might not be able to connect.

The intermediate bundle can be passed as the `cacert_file` to Erlang's SSL library.

```ini
; TODO: need new example
[ssl]
key_file    = /full/path/to/server_key.pem
cert_file   = /full/path/to/server_cert.pem
cacert_file = /full/path/to/bundle.pem
```

Now the required certificate chain will be sent to the user-agent.

## Ode to Debugging SSL

At this point, I expected to be done. Unfortunately, while OpenSSL and tools such as [sslyze](https://github.com/iSECPartners/sslyze) would connect fine, my copies of Chrome, Firefox, and curl refused to connect with cryptic SSL errors such as `ERR_SSL_CLIENT_AUTH_SIGNATURE_FAILED` and `sec_error_invalid_key`. The  net-internals of Chrome, provided no additional information.

With Wireshark, I logged traffic on port 6984, and found that the client and server exchanged `ClientHello`, `ServerHello`, `Certificate`, `ServerKeyExchange`, and `ServerHelloDone` before the browser unexpectedly closed the connection.

Inspecting the ServerHello message informed me the server agreed on using TLS 1.2 and choose the `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` cipher suite. Both supported by the browser.

From [RFC4492](http://tools.ietf.org/rfc/rfc4492.txt), in ECDHE_ECDSA, ECDHE_RSA, and ECDH_anon the ServerKeyExchange message contains the ECDHE public key use to derive the shared key. A snippet of the TLS handshake from the server to the client is replicated below.

```
0000   0c 00 01 49 03 00 16 41 04 b2 33 23 71 c9 da 80
0010   94 d3 ec eb 05 9f e5 36 91 a7 e2 e5 40 78 aa 03
0020   38 4f eb 7c 36 1b 92 21 58 cf c3 e5 b7 08 40 5a
0030   6a eb d2 6a 22 90 e0 47 28 ce 70 9b bb 87 17 d3
0040   4a bc 7c 78 14 ef 97 0d 0d 02 01 01 00 91 7e 3c
0050   ce 9f 06 1d 00 47 4f 53 85 df 2e 04 31 9a 14 a3
0060   25 bd 51 b3 1a 0f dd 3b c3 f4 25 b0 23 d5 34 0a
0070   a3 fc 2a e2 08 34 29 87 00 91 0e 10 6a 40 b3 b5
0080   61 0c 77 9a 8a 0c 50 dc 78 57 ab 2a 51 66 d0 0d
0090   b7 3c 4d c0 28 b9 06 b4 f5 f6 48 f6 5a 02 c2 7e
00a0   8f b2 ac 4b 03 3a 40 c0 e2 c6 2f 77 61 58 ea 0d
00b0   ab 6c 7f 57 be e1 03 0b c6 1e 2a b0 67 ab c2 db
00c0   0a 5b c4 ab 51 9a 76 e6 75 2d e6 ca ce 06 4b f5
00d0   8f dc f0 c1 42 65 14 c0 79 80 51 f2 68 3b 4a 51
00e0   0d 50 5a 01 32 e3 5c 8d cd 8c ec c1 c4 fa 84 3a
00f0   33 37 4c 9d d5 54 f9 6c aa b8 27 27 7b 4a 7c 33
0100   27 8e 48 48 33 87 73 11 9b 92 0b e3 99 49 23 7b
0110   c5 ab 53 ef f2 86 df 56 e5 97 6b 2d 93 5f c0 8a
0120   e6 68 4f 6b 3a 1b 55 26 08 aa c0 36 74 21 ed cc
0130   0e c9 22 0b 97 51 c1 01 48 3f 01 d2 74 fe 36 18
0140   5f 5c 91 47 b3 19 1c 00 69 7f 17 1b c3
```

* `0c` indicates this message is a ServeryKeyExchange message
* `00 01 49` is the length of 0x000149 (in decimal, 329) bytes
* `03` is the elliptical curve type, in this case "named_curve"
* `00 16` is the named curve, `secp256k1`
* What follows is the ECDHE public key and the signature.

At this point the browser verifies the signature and retrieves the elliptic curve parameters and ECDHE public key from the ServerKeyExchange message. Section 5.4 of RFC4492 ends with the following note:

> A possible reason for a fatal handshake failure is that the client's capabilities for handling elliptic curves and point formats are exceeded

While Erlang supports all 25 elliptic curves named in RFC4492, my browsers only support three: secp192r1, secp224r1, and secp256r1. In the above snippet, we see that Erlang choose secp256k1, the elliptic curve used in [Bitcoin](https://en.bitcoin.it/wiki/Secp256k1).

The version of Erlang shipped with Ubuntu 13.10 has an issue where it doesn't consider the elliptic curves the client announces it supports in the ClientHello message when picking a cipher for the ServerKeyExchange. This had been resolved with the  [Erlang R16R03-1](http://www.erlang.org/download_release/23) release.

## Configuration of TLS and Ciphers

Erlang's SSL library has defaults for the TLS versions, cipher suites and renegotiation behavior. You may want to change these options for client compatiblity and for resiliency to TLS attacks.

```erlang
% new example neeeded
```

[CloudFlare publishes](https://support.cloudflare.com/hc/en-us/articles/200933580) the cipher suites they use with nginx, though unfortunately Erlang doesn't yet support all of them. You can check the ciphers supported by your installation by  running the following in a `erl` session.

```erlang
rp(ssl:cipher_suites(openssl)).
```

I created [a patch](https://git-wip-us.apache.org/repos/asf?p=couchdb.git;a=commit;h=fdb2188) for CouchDB that has been included in the 1.6.0 release that adds the configuration options `secure_renegotiate`, `ciphers`, and `tls_versions` to the SSL section:

```ini
[ssl]
secure_renegotiate = true
tls_versions       = [ "tlsv1.1", "tlsv1.2" ]
ciphers            = [ "ECDHE-ECDSA-AES128-SHA256", "ECDHE-ECDSA-AES128-SHA" ]
```
