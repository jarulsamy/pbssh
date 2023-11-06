from setuptools import setup

from pbssh import __version__

if __name__ == "__main__":
    descrip = "A wrapper over SSH commands which grabs credentials from Passbolt."
    setup(
        name="pbssh",
        version=__version__,
        description=descrip,
        long_description=descrip,
        author="Joshua Arulsamy",
        author_email="joshua.gf.arul@gmail.com",
        license="MIT",
        packages=["pbssh"],
        install_requires=[
            "pgpy~=0.6.0",
            "requests~=2.31.0",
        ],
        entry_points={
            "console_scripts": [
                "pbssh = pbssh.pbssh:main",
            ]
        }
    )
