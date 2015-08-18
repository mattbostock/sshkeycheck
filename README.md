# SSH key checker

A small SSH server written in Go that checks any public keys
presented to it for:

- [known weak keys][] vulnerable to the [Debian PRNG bug][]
- potentially weak key lengths, e.g. 1024-bit RSA keys
- DSA (ssh-dss) keys, which [OpenSSH no longer supports by default][]

The results are output back to the user over the SSH session.

## Demo

In a terminal, connect to:

```
ssh keycheck.mattbostock.com
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
