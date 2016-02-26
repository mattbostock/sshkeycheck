# SSH key checker

A small SSH server written in Go that checks any public keys
presented to it for:

- [known weak keys][] vulnerable to the [Debian PRNG bug][]
- potentially weak key lengths, e.g. 1024-bit RSA keys
- DSA (ssh-dss) keys, which [OpenSSH no longer supports by default][]

The results are output back to the user over the SSH session.

## Example output

```
$ ssh keycheck.mattbostock.com
This server checks your SSH public keys for known or potential
security weaknesses.

For more information, please see:
https://github.com/mattbostock/sshkeycheck

The public keys presented by your SSH client are:

Bits  Type                 Fingerprint                                      Issues
4096  ssh-rsa              ed:9a:d2:5d:7b:c0:e5:cf:b9:bc:5c:6b:ce:3a:db:20  No known issues
1024  ssh-dss              4a:0d:9b:b7:92:ba:0a:93:2a:2f:27:d7:58:73:74:91  DSA KEY
384   ecdsa-sha2-nistp384  d8:99:74:7a:0b:d0:e0:be:d0:b1:93:ee:ee:0f:b5:a4  No known issues

WARNING:  You are using DSA (ssh-dss) key(s), which are no longer supported by
          default in OpenSSH 7.0 and above.
          Consider replacing them with a new RSA or ECDSA key.

Connection to keycheck.mattbostock.com closed.
```

## Inspiration

This toy project is heavily inspired by [Filippo Valsorda][]'s [whosthere][] server,
which infers your name from the SSH public keys associated with your GitHub account.

I wanted to provide an easy way for anyone to check if the SSH key they are using
is reasonably secure, in so far as we can define 'secure' from the key length
and from lists of known weak keys.

Kudos to [Ben Cox][] for raising awareness of [weak SSH keys on GitHub][].

## Disclaimer

I'm not a cryptographer, nor am I an expert in SSH. Use at your own risk and discretion.

If you spot any problems, please raise an issue. Pull requests are also welcome.

[known weak keys]: https://github.com/g0tmi1k/debian-ssh
[Debian PRNG bug]: https://www.debian.org/security/2008/dsa-1571
[Filippo Valsorda]: https://twitter.com/FiloSottile
[whosthere]: https://github.com/FiloSottile/whosthere
[Ben Cox]: https://twitter.com/Benjojo12
[weak SSH keys on GitHub]: https://blog.benjojo.co.uk/post/auditing-github-users-keys
[OpenSSH no longer supports by default]: http://www.openssh.com/txt/release-7.0
