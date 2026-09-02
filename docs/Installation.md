# Installation

First, you ought to grab the repository. You can do this with the following
command:

```sh
$ git clone https://bitbucket.org/axonibyte/ddwill
```

or

```sh
$ git clone git@bitbucket.org:axonibyte/ddwill
```

Once you've got that, you'll need to install it. Make sure that
[Rust](https://www.rust-lang.org/) 1.85 or newer is installed, and then:

```sh
cargo build --release
```

The artifact should show up at `target/release/ddwill`.


**Alternatively,** if the binaries have been prebuilt they will be available
[here](https://bitbucket.org/axonibyte/ddwill/downloads) somewhere.

You can put that file anywhere you desire, just make sure it's executable. If
you're on a *NIX-like system, you can probably run the following:

```sh
$ sudo mv path/to/ddwill /usr/local/bin/ddwill && sudo chmod a+x /usr/local/bin/ddwill
```
