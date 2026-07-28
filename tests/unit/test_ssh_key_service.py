"""Unit tests for services.ssh_key_service.calculate_ssh_fingerprint_sha256.

The expected fingerprints below are ground truth from OpenSSH's own
`ssh-keygen -lf <pubkey>`, so these tests assert the function matches OpenSSH.
"""

import pytest

from services.ssh_key_service import calculate_ssh_fingerprint_sha256

ED25519_PUBKEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIGm2vOvAVHbdQ7JkCDxqnNmXhgU3wNyzWQ5/fSS6R/3p "
    "test@example"
)
ED25519_FP = "SHA256:wH9O7TmfM7+ftOgXxwg9YCM/Iiknm7rK1ZEyQAyP+NA"

RSA_PUBKEY = (
    "ssh-rsa "
    "AAAAB3NzaC1yc2EAAAADAQABAAABAQCT9OrQLVgVKaR6SW/77GSxc46/Bn+/K2iff24MLBmH"
    "WpfVvEUrk3KJRmUreFMYJBYzwS03OxvKyIKRtcSbjOKJGJu4x93c0m54TzjDKhF45maKaz0+"
    "dsO+uqAl/YAaZmzkmZOOrWfA7+TjW1ghp5AzXrr3I+0JA65KrEYS87E0/q785eJLre6Gjo/8"
    "LtMIFBwtmDdzhZfTtN62/LQDMtRmkrKND/VjZpg/01Mj0YxSi42OkjBSj1J8KoKApsEpBNbr"
    "5LJhCaQ8NudV0fY+O9keaJMCEaoIT2oDjH46/Tuf8+AVsw2Ct3OLmmOLkSb5YeGtwAi7TOGs"
    "YbkxrrnKe3xP rsa@example"
)
RSA_FP = "SHA256:25W9dQlNA9wj1aW4yLVNnLjFPLHQzGCPyRckW6o/bPg"


@pytest.mark.parametrize(
    "pubkey, expected",
    [(ED25519_PUBKEY, ED25519_FP), (RSA_PUBKEY, RSA_FP)],
)
def test_matches_openssh_fingerprint(pubkey, expected):
    assert calculate_ssh_fingerprint_sha256(pubkey) == expected


def test_accepts_bare_key_body_without_type_prefix():
    # When only one token is given, the body itself is used.
    body = ED25519_PUBKEY.split()[1]
    assert calculate_ssh_fingerprint_sha256(body) == ED25519_FP


def test_no_padding_in_output():
    assert not calculate_ssh_fingerprint_sha256(ED25519_PUBKEY).endswith("=")


@pytest.mark.parametrize("value", ["", None])
def test_missing_key_returns_message(value):
    assert (
        calculate_ssh_fingerprint_sha256(value)
        == "Invalid key: missing SSH public key."
    )


def test_invalid_base64_returns_invalid_key():
    # '!!!!' is not valid base64 (validate=True rejects it).
    assert calculate_ssh_fingerprint_sha256("ssh-rsa !!!!") == "Invalid key"
