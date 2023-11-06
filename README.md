# Passbolt SSH

> **Disclaimer:** This is a community driven project and it is not associated with
> Passbolt SA.

Consider this situation; you're a system administrator (or just someone with a
lot of different hosts with many different passwords) and you need to
frequently SSH into a variety of different machines. You store all your
passwords in Passbolt, but you hate having to copy/paste passwords all the time.
Welcome to `pbssh`, a thin wrapper on top of SSH which automatically grabs
passwords from Passbolt.

## Usage

Just substitute `pbssh` wherever you use `ssh`. On the first run you'll get
some instructions on how to set up the configuration file.

After set up, `pbssh` will attempt to match the username and host specified on
the CLI to username and URI entries on a Passbolt entry. If nothing matches, it
falls back to normal password authentication. You will be prompted for the GPG
key passphrase each time.

In case you want to pass any additional flags to `ssh`, just include them after
the host, for example.

```shell
# I want X11 forwarding
$ pbssh root@my-home-server -X

# I just want the hostname (for some reason...)
$ pbssh root@my-home-server hostname
```

## Disclaimer

I wrote this in a day, all in a single session, there are probably edge cases I
haven't considered.

## License

Refer to [LICENSE](./LICENSE).
