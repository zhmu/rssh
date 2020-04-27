# r-ssh

## Introduction

This is my attempt at a SSH 2.0 client. It is (almost) usable but hasn't had any security-review - you have been warned.

## Supported protocols

Note: the only supported key exchange algorithm has been deprecated due to the Logjam Attack - this means this SSH client cannot be used until a more recent protocol has been added.

- Key exchange algorithms: diffie-hellman-group14-sha1
- Encryption: AES128-CBC
- HMAC: HMAC-SHA1
- Compression: none

## License

The code uses the excellent Crypto++ library by Wei Dai - version 5.6.5 is bundled with this, which is licensed under the Boost Software License (even though all individual files are public domain). Everything else is beer-ware:

```
"THE BEER-WARE LICENSE" (Revision 42): Rink Springer <rink@rink.nu> wrote
this file. As long as you retain this notice you can do whatever you want
with this stuff. If we meet some day, and you think this stuff is worth it,
you can buy me a beer in return Rink Springer
```

## Testing

You can use an OpenSSH server with the following sshd_config settings:

```
Ciphers 3des-cbc,aes128-cbc,aes128-ctr
Compression no
HostKey /etc/ssh/ssh_host_rsa_key
KexAlgorithms diffie-hellman-group14-sha1
Port 2222
MACs hmac-sha1
UsePrivilegeSeparation no
UsePAM yes
```

You should then be able to connect to it using ``rssh -d localhost:2222`` (the ``-d`` flag enables all trace messages)

## References

Throughout the source code, references are made to specifications. These are:

- [SSH-ARCH] Ylonen, T. and C. Lonvick, Ed., "The Secure Shell (SSH) Protocol Architecture", RFC 4251, January 2006.
- [SSH-TRANS] Ylonen, T. and C. Lonvick, Ed., "The Secure Shell (SSH) Transport Layer Protocol", RFC 4253, January 2006.
- [SSH-USERAUTH] Ylonen, T. and C. Lonvick, Ed., "The Secure Shell (SSH) Authentication Protocol", RFC 4252, January 2006.
- [SSH-NUMBERS] Lehtinen, S. and C. Lonvick, Ed., "The Secure Shell (SSH) Protocol Assigned Numbers", RFC 4250, January 2006.  
- [KBD-INT] Cusack, F. and Forssen, M. "Generic Message Exchange Authentication for the Secure Shell Protocol (SSH)", RFC 4256, January 2006.
