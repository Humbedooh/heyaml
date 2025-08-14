# heyaml
Python port of a subset of Hiera EYAML

### Caveats
_This is an early prototype, subject to many upcoming changes and documentation efforts._

## Introduction
`heyaml` is a simple python port and refactoring of basic EYAML functionality used in Hiera-backed Puppet setups.

At present, `heyaml` is hardcoded to use GPG encryption through the `python-gnupg` library, though alternate methods may appear in the future.

`heyaml` supports the following actions, some of which did not exist in the original hiera-eyaml Ruby package:

- `create` and `edit` an EYAML document using your choice of text editor
- `validate` an existing EYAML document, asserting that the document can be decrypted by everyone in the gpg recipients list
- `recrypt` a file, re-encrypting any secrets whose recipient list does not match the current list
- `cat` an EYAML file, essentially displaying the decrypted version on the command line

`heyaml` also supports  write-only editing for users working with EYAML documents that they do not have access to decrypt, whether fully or partially. This mode allows contributors to add, remove, or update secrets without being able to see the decrypted contents. Only secrets that have been altered will be re-encrypted to the EYAML file.

## Installation
The simplest way to install and use heyaml is with [`uv`](https://github.com/astral-sh/uv):

```shell
git clone https://github.com/Humbedooh/heyaml.git
cd heyaml
uv init
uv run heyaml.py -h
```

## Basic usage

```shell
Usage: heyaml.py [-h] [-p PUPPETDIR] [-g GPGHOME] {cat,create,edit,recrypt,validate} [filename ...]

positional arguments:
  {cat,create,edit,recrypt,validate}
  filename              Path to the EYAML file(s) to open

options:
  -h, --help            show this help message and exit
  -p, --puppetdir PUPPETDIR
                        Path to the base puppet directory, if not current dir
  -g, --gpghome GPGHOME
                        Path to the GPG homedir (otherwise uses ~/.gnupg)

```

`heyaml` supports batching operations, either by listing multiple filenames to perform an action on, or by using Glob syntax.
