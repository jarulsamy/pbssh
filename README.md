<h1 align="center">Passbolt SSH</h1>
<p align="center">
<img alt="Python Versions" src="https://img.shields.io/pypi/pyversions/pbssh">
<a href="https://pypi.org/project/pbssh/"><img alt="PyPI" src="https://img.shields.io/pypi/v/pbssh"></a>
<img alt="Total LOC" src="https://img.shields.io/tokei/lines/github/jarulsamy/pbssh">
<a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
<a href="https://github.com/jarulsamy/pbssh/blob/master/LICENSE"><img alt="License" src="https://img.shields.io/github/license/jarulsamy/pbssh"></a>
</p>

> **Disclaimer:** This is a community driven project and it is not associated with
> Passbolt SA.

Consider this situation; you're a system administrator (or just someone with a
lot of different hosts with many different passwords) and you need to
frequently SSH into a variety of different machines. You store all your
passwords in Passbolt, but you hate having to copy/paste passwords all the time.
Welcome to `pbssh`, a thin wrapper on top of SSH which automatically grabs
passwords from Passbolt.

## Installation

Assuming you have Python 3.9+ and pip installed already it should be as simple as:

```shell
$ pip install pbssh
```

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
