#!/usr/bin/env drgn
# Copyright (c) Meta Platforms, Inc. and affiliates.
# SPDX-License-Identifier: LGPL-2.1-or-later

"""Dump the master key of a dm-crypt device that uses aes-xts-plain64."""

import argparse
import os
from pathlib import Path
import sys

from drgn import cast, container_of
from drgn.helpers.linux.block import disk_name, for_each_disk


def crypto_skcipher_alg(tfm):
    return container_of(tfm.base.__crt_alg, "struct skcipher_alg", "base")


def crypto_skcipher_ctx(tfm):
    return cast("void *", tfm.base.__crt_ctx)


def crypto_lskcipher_ctx(tfm):
    return cast("void *", tfm.base.__crt_ctx)


def aes_xts_ctx(tfm):
    AESNI_ALIGN = 16
    mask = AESNI_ALIGN - 1
    ctx = cast("unsigned long", crypto_skcipher_ctx(tfm))
    return cast("struct aesni_xts_ctx *", (ctx + mask) & ~mask)


def aes_key_from_ctx(ctx):
    words = ctx.key_enc.value_()[: ctx.key_length / 4]
    return b"".join(word.to_bytes(4, "little") for word in words)


def is_function(obj, name):
    try:
        global_ = obj.prog_[name]
    except KeyError:
        return False
    return obj == global_


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("name")
    args = parser.parse_args()

    if "/" in args.name:
        device_path = Path(args.name)
    else:
        device_path = Path("/dev/mapper") / args.name
    name = os.fsencode(device_path.resolve().name)

    for disk in for_each_disk():
        if disk_name(disk) == name:
            break
    else:
        sys.exit("target not found")

    md = cast("struct mapped_device *", disk.private_data)
    map = cast("struct dm_table *", md.map)

    if map.num_targets != 1:
        sys.exit("dm table has multiple targets")
    ti = map.targets

    if not is_function(ti.type.map, "crypt_map"):
        sys.exit("target is not dm-crypt")
    cc = cast("struct crypt_config *", ti.private)

    if cc.cipher_string.string_() != b"aes-xts-plain64":
        sys.exit("cipher is not aes-xts-plain64")

    tfm = cc.cipher_tfm.tfms[0]
    exit = crypto_skcipher_alg(tfm).exit.read_()
    if is_function(exit, "simd_skcipher_exit"):
        cryptd_tfm = cast(
            "struct simd_skcipher_ctx *", crypto_skcipher_ctx(tfm)
        ).cryptd_tfm
        cryptd_ctx = cast(
            "struct cryptd_skcipher_ctx *", crypto_skcipher_ctx(cryptd_tfm.base)
        )
        child_tfm = cryptd_ctx.child
        xts_ctx = aes_xts_ctx(cryptd_ctx.child)
        crypt_aes_ctx = xts_ctx.crypt_ctx
        tweak_aes_ctx = xts_ctx.tweak_ctx
    elif is_function(exit, "xts_exit_tfm"):
        xts_ctx = cast("struct xts_tfm_ctx *", crypto_skcipher_ctx(tfm))
        lskcipher_tfm = cast(
            "struct crypto_lskcipher **", crypto_skcipher_ctx(xts_ctx.child)
        )[0]
        cipher_tfm = cast(
            "struct crypto_cipher **", crypto_lskcipher_ctx(lskcipher_tfm)
        )[0]
        crypt_aes_ctx = cast("struct crypto_aes_ctx *", cipher_tfm.base.__crt_ctx)
        tweak_aes_ctx = cast("struct crypto_aes_ctx *", xts_ctx.tweak.base.__crt_ctx)
    else:
        sys.exit("unknown skcipher")
    print(aes_key_from_ctx(crypt_aes_ctx).hex())
    print(aes_key_from_ctx(tweak_aes_ctx).hex())


if __name__ == "__main__":
    main()
