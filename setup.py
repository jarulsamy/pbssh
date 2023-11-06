from setuptools import setup

from pbssh import __version__

if __name__ == "__main__":
    setup(
        name="pbssh",
        version=__version__,
        description="A wrapper over SSH commands which grabs credentials from Passbolt.",
        author="Joshua Arulsamy",
        email="joshua.gf.arul@gmail.com",
        license="MIT",
        packages=["pbssh"],
    )
