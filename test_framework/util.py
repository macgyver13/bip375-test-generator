#!/usr/bin/env python3
# Copyright (c) 2014-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Trimmed subset of Bitcoin Core's test_framework/util.py.

Only the helpers used by the vendored messages/script/script_util/key/psbt/crypto
modules are kept here; the full file pulls in test-runner machinery
(authproxy, coverage, descriptors) that this project does not need.
"""

import random


def assert_equal(thing1, thing2, *args):
    if thing1 != thing2 or any(thing1 != arg for arg in args):
        raise AssertionError("not(%s)" % " == ".join(str(arg) for arg in (thing1, thing2) + args))


def assert_not_equal(thing1, thing2, *, error_message=""):
    if thing1 == thing2:
        raise AssertionError(f"Both values are {thing1}{f', {error_message}' if error_message else ''}")


def assert_greater_than(thing1, thing2):
    if thing1 <= thing2:
        raise AssertionError("%s <= %s" % (str(thing1), str(thing2)))


def assert_greater_than_or_equal(thing1, thing2):
    if thing1 < thing2:
        raise AssertionError("%s < %s" % (str(thing1), str(thing2)))


def random_bitflip(data):
    data = list(data)
    data[random.randrange(len(data))] ^= (1 << (random.randrange(8)))
    return bytes(data)
