#!/usr/bin/env python3
#  Licensed to the Apache Software Foundation (ASF) under one or more
#  contributor license agreements.  See the NOTICE file distributed with
#  this work for additional information regarding copyright ownership.
#  The ASF licenses this file to You under the Apache License, Version 2.0
#  (the "License"); you may not use this file except in compliance with
#  the License.  You may obtain a copy of the License at
#      http://www.apache.org/licenses/LICENSE-2.0
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
"""heyaml.py - a Python interface for managing Hiera EYAML secrets"""

import gnupg
import ruamel.yaml
import sys
import os
import subprocess
import tempfile
import argparse
import hashlib
import io
import requests


BLAKE_LEN = 8
FALLBACK_EDITOR = "nano"
YAML_WIDTH = 16 * 1024


class YamlTag:
    """A class that represents a type of enclosing tag for denoting a certain type of data"""
    def __init__(self, open_tag: str, close_tag: str):
        self.tag_open = open_tag
        self.tag_close = close_tag

    def match(self, data: str):
        """Tests whether a string value matches a tag specification. If matched, returns the enclosed string value, otherwise None"""
        if data.startswith(self.tag_open) and data.endswith(self.tag_close):
            return data[len(self.tag_open) : -len(self.tag_close)]
        return None

    def enclose(self, data: str):
        """Encloses a string value in the tag format"""
        return f"{self.tag_open}{data}{self.tag_close}"


HEYAML_TAG_ENCRYPT = YamlTag(open_tag="ENC{{", close_tag="}}")
HIERA_TAG_ENCRYPTED_GPG = YamlTag(open_tag="ENC[GPG,", close_tag="]")
HEYAML_TAG_PLACEHOLDER = YamlTag(open_tag="*** [HEYAML:", close_tag=": UNABLE TO DECRYPT THIS SECRET, OVERRIDE ONLY] ***")
GPG_TAG = YamlTag(open_tag="\n-----BEGIN PGP MESSAGE-----\nVersion: 2.6.2\n\n", close_tag="\n-----END PGP MESSAGE-----\n")
HEYAML_PREAMBLE = """
# This is the decrypted YAML document, to the extent that Heyaml can decrypt it.
# Any string values that should be encrypted in the resulting EYAML document are
# denoted with the ENC{{}} tag enclosing it, for instance: ENC{{secret goes here}}
# Any string value not inside an ENC{{}} tag will be written into EYAML as plain-text.
#
# Values that could not be decrypted are replaced by a placeholder tag with a reference
# to the original encrypted text. If the tag is not modified or replaced with another
# value, the tag will revert back to the original encrypted text upon exiting the editor.

"""

class CryptException(BaseException):
    pass


class CryptYAML:
    def __init__(self, original_eyaml: str = "", expected_recipients: str|os.PathLike = None):
        self.parser = ruamel.yaml.YAML(typ="safe", pure=True)
        self.parser.width = YAML_WIDTH
        self.parser.default_flow_style = False
        self.parser.indent(mapping=2, offset=2)
        self.parser.representer.add_representer(str, self.str_repr)
        self.parser.constructor.add_constructor("tag:yaml.org,2002:str", self.str_construct)
        self.recipient_diff = set()
        self.expected_recipients = {}
        self.original_eyaml = original_eyaml
        self.secrets = {}
        self.is_encrypting = False
        if expected_recipients:
            for identifier in [line.strip() for line in open(expected_recipients).readlines() if not line.startswith("#")]:
                # We can use external GPG keys over HTTPS as well as email address identifiers:
                if identifier.startswith("https://"):
                    gpg_data = requests.get(identifier)
                    gpg_data.raise_for_status()
                    remote_keys: gnupg.ImportResult = gpg.import_keys(gpg_data.text)
                    if remote_keys.fingerprints:
                        new_identifier = remote_keys.fingerprints[0]
                        for key in gpg.list_keys(keys=new_identifier):
                            if key["trust"] not in  ("f", "u"): #
                                if not input(f"GPG key {new_identifier} from {identifier} is new, press enter to trust it or ctrl+c to cancel out: "):
                                    sys.stderr.write(f"[INFO] Trusting {new_identifier} with TRUST_ULTIMATE.")
                                    gpg.trust_keys(new_identifier, "TRUST_ULTIMATE")
                        identifier = new_identifier
                    else:
                        sys.stderr.write(f"[WARNING] GPG reference {identifier} in {expected_recipients} is blank, ignoring.\n")
                        continue
                self.expected_recipients[identifier] = []
                for key in gpg.list_keys(keys=identifier):
                    self.expected_recipients[identifier].append(key["keyid"])
                    self.expected_recipients[identifier].extend([k for k in key.get("subkey_info", {}).keys()])
        if self.original_eyaml:

            self.decrypted_yaml = self.decrypt()
        else:
            self.decrypted_yaml = {}

    def decrypt(self):
        decrypted_dict = self.parser.load(self.original_eyaml)
        return decrypted_dict

    def encrypt(self, yml: dict, filename: str):
        self.is_encrypting = True
        tmpio = io.StringIO()
        try:
            self.parser.dump(yml, tmpio)
        except CryptException as e:
            print(f"Could not encrypt document {filename}: {e}")
            sys.exit(-1)
        with open(filename, "w") as f:
            f.write(tmpio.getvalue())

    def print_diff(self):
        difftxt = ""
        if self.recipient_diff:
            for el in self.recipient_diff:
                if el.startswith("-"):
                    difftxt += f"- Content encrypted for {el[1:]} but key is no longer in hiera-eyaml-gpg.recipients\n"
                else:
                    difftxt += f"- Content not encrypted for {el[1:]} but address was found in hiera-eyaml-gpg.recipients\n"
        return difftxt

    def tempedit(self) -> dict:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(HEYAML_PREAMBLE.lstrip())
            if self.decrypted_yaml:
                self.is_encrypting = False
                self.parser.dump(self.decrypted_yaml, f)
            f.close()
            proc = subprocess.Popen(
                (
                    os.environ.get("EDITOR", FALLBACK_EDITOR),
                    f.name,
                )
            )
            proc.wait()
            newyaml = self.parser.load(open(f.name).read())
            os.unlink(f.name)
            return newyaml

    def str_construct(self, node, tag):
        if not self.is_encrypting and (ft := HIERA_TAG_ENCRYPTED_GPG.match(tag.value)):
            recips = gpg.get_recipients(GPG_TAG.enclose(ft))
            if self.expected_recipients:
                for expected_email, expected_keys in self.expected_recipients.items():
                    if not any(key in recips for key in expected_keys):
                        self.recipient_diff.add(f"+{expected_email}")  # email needs to be added to crypt list
                for recip in recips:
                    if all(recip not in keys for keys in self.expected_recipients.values()):
                        self.recipient_diff.add(f"-{recip}")  # Key needs to be removed from crypt list
            cryptobject = gpg.decrypt(GPG_TAG.enclose(ft))
            if cryptobject.ok:
                tag.value = HEYAML_TAG_ENCRYPT.enclose(str(cryptobject))
            else:
                blakeid = hashlib.blake2s(tag.value.encode("utf-8"), digest_size=BLAKE_LEN).hexdigest()
                self.secrets[blakeid] = str(ft)
                tag.value = HEYAML_TAG_PLACEHOLDER.enclose(blakeid)
        return tag.value

    def str_repr(self, dumper, data):
        self.parser.width = YAML_WIDTH
        if self.is_encrypting:
            if blakeid := HEYAML_TAG_PLACEHOLDER.match(data):
                self.parser.width = 16 * 1024
                if blakeid in self.secrets:
                    print(f"Notice: could not decrypt original value for {blakeid}, leaving intact and not re-encrypting")
                    data = self.secrets[blakeid].strip()
                    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="")
                else:
                    print(f"MISSING: {blakeid}")
            elif to_encrypt := HEYAML_TAG_ENCRYPT.match(data):
                encrypted_data = gpg.encrypt(to_encrypt, recipients=list(self.expected_recipients.keys()))
                if encrypted_data.ok:
                    encrypted_data = "".join(str(encrypted_data).splitlines()[2:][:-2])
                else:
                    raise CryptException(encrypted_data.status_detail)
                data = HIERA_TAG_ENCRYPTED_GPG.enclose(encrypted_data)
        if len(data.splitlines()) > 1:  # If this is a multiline string, use the pipe indicator
            return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
        # If single-line string, just use default style
        return dumper.represent_scalar("tag:yaml.org,2002:str", data)


gpg = gnupg.GPG()


def main():
    cwd = os.getcwd()
    homedir = os.getenv("GNUPGHOME", os.path.join(os.getenv("HOME", cwd), ".gnupg"))
    parser = argparse.ArgumentParser(prog="heyaml.py")
    parser.add_argument("-p", "--puppetdir", help=f"Path to the base puppet git dir, if not current dir ({cwd})", default=cwd)
    parser.add_argument("-r", "--recipients", help=f"Path to the hiera recipients list. Supersedes the --puppetdir option if specified")
    parser.add_argument("-g", "--gpghome", help=f"Path to the GPG homedir (otherwise uses {homedir})", default=homedir)
    parser.add_argument("action", choices=("cat", "create", "edit", "recrypt", "validate"))
    parser.add_argument("filename", help="Path to the EYAML file(s) to open", nargs="*")

    args = parser.parse_args()

    if args.gpghome:
        gpg.gnupghome = args.gpghome

    # Read puppet encryption recipients file
    puppet_recips = args.recipients or os.path.join(args.puppetdir, "data/hiera-eyaml-gpg.recipients")

    for filename in args.filename:

        # Load EYAML file if applicable and available
        if os.path.isfile(filename):
            cyaml = CryptYAML(original_eyaml=open(filename).read(), expected_recipients=puppet_recips)
            inyaml = cyaml.decrypt()
        elif args.action in ("cat", "recrypt"):
            sys.stderr.write(f"File not found: {filename}")
            sys.exit(-1)
        else:
            inyaml = {}  # Blank canvas if 'edit' on a new file
        if args.action == "cat":
            cyaml.parser.dump(inyaml, sys.stdout)
        elif args.action == "validate":
            diff = cyaml.print_diff()
            if diff:
                print(f"{filename} is valid, but encryption does not match hiera-eyaml-gpg.recipients:")
                print(diff)
                sys.exit(-1)  # exit -1 so shells can catch when diffs happen
            else:
                print(f"{filename} is valid and encryption matches hiera-eyaml-gpg.recipients:")

        elif args.action == "recrypt":
            cyaml.encrypt(inyaml, filename)
            encrypted_to = []
            for key in gpg.list_keys(keys=cyaml.expected_recipients.keys()):
                if key["uids"]:
                    encrypted_to.append(key["uids"][0])
            print(f"Re-encrypted {filename} to the following recipients: {', '.join(encrypted_to)}")
        elif args.action in ("edit", "create"):
            new_yaml_decrypted = cyaml.tempedit()
            if new_yaml_decrypted and (new_yaml_decrypted != inyaml or cyaml.recipient_diff):
                if new_yaml_decrypted == inyaml and cyaml.recipient_diff:
                    print(
                        "YAML contents unchanged, but recipients have changed since file was last encrypted:"
                    )

                cyaml.encrypt(new_yaml_decrypted, filename)
                print(f"Successfully saved changes to {filename}")
            else:
                print("No changes detected, nothing to do.")


if __name__ == "__main__":
    main()
