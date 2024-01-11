Recovering a dm-crypt Encryption Key
====================================

| Author: Omar Sandoval
| Date: January 11th, 2024

.. highlight:: pycon
.. linuxversion:: v6.7

`dm-crypt <https://docs.kernel.org/admin-guide/device-mapper/dm-crypt.html>`_
is the Linux kernel's transparent disk encryption subsystem. I recently had to
recover the master key for an encrypted disk where the passphrase was no longer
known, but the dm-crypt device was still open. Normally, the key is stored in
kernel space and cannot be accessed by user space. However, with drgn, we can
traverse kernel data structures to recover the key. This is a great example of
how to jump between kernel code and drgn to navigate a subsystem.

.. warning::

   The dm-crypt master key is obviously very sensitive information that
   shouldn't be exposed carelessly.

   As a disclaimer for anyone concerned about the security implications:
   everything is working as intended here. Debugging the live kernel with drgn
   requires ``root``, and ``root`` has many other ways to access sensitive
   information (loading kernel modules, triggering a kernel core dump, etc.).
   Solutions like `inline encryption
   <https://docs.kernel.org/block/inline-encryption.html>`_ and
   :manpage:`kernel_lockdown(7)` can be used for defense in depth if necessary.

Setup
-----

For this writeup, I'm going to set up dm-crypt in a virtual machine running
Linux 6.7.

.. code-block:: console

    # uname -r
    6.7.0
    # cryptsetup luksFormat /dev/vdb

    WARNING!
    ========
    This will overwrite data on /dev/vdb irrevocably.

    Are you sure? (Type 'yes' in capital letters): YES
    Enter passphrase for /dev/vdb: hello
    Verify passphrase: hello
    # cryptsetup open /dev/vdb mycrypt
    Enter passphrase for /dev/vdb: hello

The default configuration is `AES
<https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>`_ in `XTS
<https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS>`_ mode with a
512-bit key:

.. code-block:: console

    # cryptsetup status mycrypt
    /dev/mapper/mycrypt is active.
      type:    LUKS2
      cipher:  aes-xts-plain64
      keysize: 512 bits
      key location: keyring
      device:  /dev/vdb
      sector size:  512
      offset:  32768 sectors
      size:    33521664 sectors
      mode:    read/write

The new device is ``dm-0``:

.. code-block:: console

    # realpath /dev/mapper/mycrypt
    /dev/dm-0

Getting from Device Mapper to the Crypto API
--------------------------------------------

The `dm-crypt documentation
<https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMCrypt>`_ tells us that
"Device-mapper is infrastructure in the Linux kernel that provides a generic
way to create virtual layers of block devices. Device-mapper crypt target
provides transparent encryption of block devices using the kernel crypto API."

Our first goal is therefore to get to whatever context is used by the crypto
API, which likely includes the encryption key. To do that, we're going to have
to navigate through the device mapper code.

To start, let's find the virtual disk for our dm-crypt target in drgn using the
:meth:`~drgn.helpers.linux.block.for_each_disk()` and
:meth:`~drgn.helpers.linux.block.disk_name()` helpers:

    >>> for disk in for_each_disk():
    ...     if disk_name(disk) == b"dm-0":
    ...             print(disk)
    ...             break
    ...
    *(struct gendisk *)0xffffa3b9421b2c00 = {
            ...
    }

``struct gendisk`` has a function table, ``fops``, with callbacks to the disk
driver. Specifically, the ``submit_bio`` callback intercepts disk reads and
writes::

    >>> disk.fops.submit_bio
    (void (*)(struct bio *))dm_submit_bio+0x0 = 0xffffffffc05761e0

Let's take a look at :linux:`dm_submit_bio() <drivers/md/dm.c:1840>`:

.. code-block:: c

    static void dm_submit_bio(struct bio *bio)
    {
            struct mapped_device *md = bio->bi_bdev->bd_disk->private_data;
            int srcu_idx;
            struct dm_table *map;

            map = dm_get_live_table(md, &srcu_idx);
            ...
            dm_split_and_process_bio(md, map, bio);
            ...
    }

So the disk's private data is a ``struct mapped_device``. Let's get it in drgn::

    >>> md = cast("struct mapped_device *", disk.private_data)

:linux:`dm_get_live_table() <drivers/md/dm.c:685>` gets the device mapper
table:

.. code-block:: c

    struct dm_table *dm_get_live_table(struct mapped_device *md,
                                       int *srcu_idx) __acquires(md->io_barrier)
    {
            *srcu_idx = srcu_read_lock(&md->io_barrier);

            return srcu_dereference(md->map, &md->io_barrier);
    }

`SRCU <https://lwn.net/Articles/202847/>`_ is a synchronization mechanism which
we can blithely ignore::

    >>> map = cast("struct dm_table *", md.map)

``dm_submit_bio()`` then calls :linux:`dm_split_and_process_bio()
<drivers/md/dm.c:1771>`, which calls :linux:`__split_and_process_bio()
<drivers/md/dm.c:1711>`:

.. code-block:: c

    static blk_status_t __split_and_process_bio(struct clone_info *ci)
    {
            struct bio *clone;
            struct dm_target *ti;
            unsigned int len;

            ti = dm_table_find_target(ci->map, ci->sector);
            ...
            __map_bio(clone);
    }

:linux:`dm_table_find_target() <drivers/md/dm-table.c:1471>` finds the
appropriate device mapper target in a table:

.. code-block:: c

    struct dm_target *dm_table_find_target(struct dm_table *t, sector_t sector)
    {
            ...
            return &t->targets[(KEYS_PER_NODE * n) + k];
    }

Our simple case only has one target::

    >>> map.num_targets
    (unsigned int)1
    >>> ti = map.targets

``__split_and_process_bio()`` then calls :linux:`__map_bio()
<drivers/md/dm.c:1398>`:

.. code-block:: c

    static void __map_bio(struct bio *clone)
    {
            struct dm_target_io *tio = clone_to_tio(clone);
            struct dm_target *ti = tio->ti;
            struct dm_io *io = tio->io;
            struct mapped_device *md = io->md;
            int r;

            ...
                    if (likely(ti->type->map == linear_map))
                            r = linear_map(ti, clone);
                    else if (ti->type->map == stripe_map)
                            r = stripe_map(ti, clone);
                    else
                            r = ti->type->map(ti, clone);
            ...
    }

So we need to look at another callback::

    >>> ti.type.map
    (dm_map_fn)crypt_map+0x0 = 0xffffffffc08a03f0

:linux:`crypt_map() <drivers/md/dm-crypt.c:3411>` is part of dm-crypt, so we've
finally made it out of generic device mapper:

.. code-block:: c

    static int crypt_map(struct dm_target *ti, struct bio *bio)
    {
            struct dm_crypt_io *io;
            struct crypt_config *cc = ti->private;
            ...

And we have the dm-crypt configuration::

    >>> cc = cast("struct crypt_config *", ti.private)

Dumping it out reveals some crypto API context!

.. code-block:: pycon

    >>> cc
    *(struct crypt_config *)0xffffa3b9421b2400 = {
            ...
            .cipher_tfm = (union <anonymous>){
                    .tfms = (struct crypto_skcipher **)0xffffa3b9438667c0,
                    ...
            },
            .tfms_count = (unsigned int)1,
            ...
    }
    >>> tfm = cc.cipher_tfm.tfms[0]

Descending Down the Crypto API
------------------------------

The Linux kernel crypto API is very generic and is implemented with a lot of
runtime polymorphism. Our next goal is to traverse through the crypto API data
structures to find the key.

The crypto API refers to cryptographic ciphers as `"transformations"
<https://docs.kernel.org/6.7/crypto/intro.html>`_. Transformations can be
combined and nested in various ways. The ``tfm`` variable we found is a
`"transformation object"
<https://docs.kernel.org/6.7/crypto/intro.html#terminology>`_, which is an
instance of a transformation::

    >>> tfm
    *(struct crypto_skcipher *)0xffffa3b948218c00 = {
            .reqsize = (unsigned int)160,
            .base = (struct crypto_tfm){
                    .refcnt = (refcount_t){
                            .refs = (atomic_t){
                                    .counter = (int)1,
                            },
                    },
                    .crt_flags = (u32)0,
                    .node = (int)-1,
                    .exit = (void (*)(struct crypto_tfm *))crypto_skcipher_exit_tfm+0x0 = 0xffffffffb77d2600,
                    .__crt_alg = (struct crypto_alg *)0xffffa3b943dab448,
                    .__crt_ctx = (void *[]){},
            },
    }
    >>> tfm.base.__crt_alg
    *(struct crypto_alg *)0xffffa3b943dab448 = {
            ...
            .cra_name = (char [128])"xts(aes)",
            ...
    }

This is an ``skcipher``, or a symmetric key cipher. It is using the
``xts(aes)`` algorithm as expected. ``__crt_ctx`` is an opaque context, which
is promising if we can figure out how to interpret it. The ``exit`` callback
looks like a cleanup function. That seems like a good way for us to figure out
how ``__crt_ctx`` is used. Here are :linux:`crypto_skcipher_exit_tfm()
<crypto/skcipher.c:701>` and the :linux:`crypto_skcipher_alg()
<include/crypto/skcipher.h:384>` and :linux:`crypto_skcipher_tfm()
<include/crypto/skcipher.h:314>` getters it uses:

.. code-block:: c

    static void crypto_skcipher_exit_tfm(struct crypto_tfm *tfm)
    {
            struct crypto_skcipher *skcipher = __crypto_skcipher_cast(tfm);
            struct skcipher_alg *alg = crypto_skcipher_alg(skcipher);

            alg->exit(skcipher);
    }

    static inline struct skcipher_alg *crypto_skcipher_alg(
            struct crypto_skcipher *tfm)
    {
            return container_of(crypto_skcipher_tfm(tfm)->__crt_alg,
                                struct skcipher_alg, base);
    }

    static inline struct crypto_tfm *crypto_skcipher_tfm(
            struct crypto_skcipher *tfm)
    {
            return &tfm->base;
    }

We can emulate the getters in drgn to find the underlying implementation::

    >>> def crypto_skcipher_alg(tfm):
    ...     return container_of(tfm.base.__crt_alg, "struct skcipher_alg", "base")
    ...
    >>> crypto_skcipher_alg(tfm).exit
    (void (*)(struct crypto_skcipher *))simd_skcipher_exit+0x0 = 0xffffffffc058b1f0

My machine supports the `AES-NI
<https://en.wikipedia.org/wiki/AES_instruction_set#x86_architecture_processors>`_
x86 extension. The kernel cannot use SIMD instructions like AES-NI in some
contexts, so it has an :linuxt:`extra layer of indirection <crypto/simd.c:14>`
to go through an asynchronous daemon when necessary. This involves a couple of
wrapper transformation objects. :linux:`simd_skcipher_exit()
<crypto/simd.c:104>` shows us how to unwrap the first one:

.. code-block:: c

    static void simd_skcipher_exit(struct crypto_skcipher *tfm)
    {
            struct simd_skcipher_ctx *ctx = crypto_skcipher_ctx(tfm);

            cryptd_free_skcipher(ctx->cryptd_tfm);
    }

We just need one more getter in drgn, :linux:`crypto_skcipher_ctx()
<include/crypto/internal/skcipher.h:225>`::

    >>> def crypto_skcipher_ctx(tfm):
    ...     return cast("void *", tfm.base.__crt_ctx)
    ...
    >>> simd_ctx = cast("struct simd_skcipher_ctx *", crypto_skcipher_ctx(tfm))
    >>> cryptd_tfm = simd_ctx.cryptd_tfm
    >>> cryptd_tfm
    *(struct cryptd_skcipher *)0xffffa3b94b5e4cc0 = {
            .base = (struct crypto_skcipher){
                    .reqsize = (unsigned int)80,
                    .base = (struct crypto_tfm){
                            .refcnt = (refcount_t){
                                    .refs = (atomic_t){
                                            .counter = (int)1,
                                    },
                            },
                            .crt_flags = (u32)0,
                            .node = (int)-1,
                            .exit = (void (*)(struct crypto_tfm *))crypto_skcipher_exit_tfm+0x0 = 0xffffffffb77d2600,
                            .__crt_alg = (struct crypto_alg *)0xffffa3b9421b2848,
                            .__crt_ctx = (void *[]){},
                    },
            },
    }

We saw ``crypto_skcipher_exit_tfm()`` earlier, so we know where to look next::

    >>> crypto_skcipher_alg(cryptd_tfm.base).exit
    (void (*)(struct crypto_skcipher *))cryptd_skcipher_exit_tfm+0x0 = 0xffffffffc04d6210

:linux:`cryptd_skcipher_exit_tfm() <crypto/cryptd.c:358>` shows us how to
unwrap this transformation object:

.. code-block:: c

    static void cryptd_skcipher_exit_tfm(struct crypto_skcipher *tfm)
    {
            struct cryptd_skcipher_ctx *ctx = crypto_skcipher_ctx(tfm);

            crypto_free_skcipher(ctx->child);
    }

Now we can get the actual cipher transformation object::

    >>> cryptd_ctx = cast("struct cryptd_skcipher_ctx *", crypto_skcipher_ctx(cryptd_tfm.base))
    >>> child_tfm = cryptd_ctx.child
    >>> child_tfm
    *(struct crypto_skcipher *)0xffffa3b945dc4000 = {
            .reqsize = (unsigned int)0,
            .base = (struct crypto_tfm){
                    .refcnt = (refcount_t){
                            .refs = (atomic_t){
                                    .counter = (int)1,
                            },
                    },
                    .crt_flags = (u32)0,
                    .node = (int)-1,
                    .exit = (void (*)(struct crypto_tfm *))0x0,
                    .__crt_alg = (struct crypto_alg *)0xffffffffc05e7d80,
                    .__crt_ctx = (void *[]){},
            },
    }

This one doesn't have an exit callback, so let's look at the algorithm::

    >>> crypto_skcipher_alg(child_tfm)
    *(struct skcipher_alg *)0xffffffffc05e7d40 = {
            .setkey = (int (*)(struct crypto_skcipher *, const u8 *, unsigned int))xts_aesni_setkey+0x0 = 0xffffffffc059efb0,
            ...
    }

:linux:`xts_aesni_setkey() <arch/x86/crypto/aesni-intel_glue.c:880>` is very
enlightening:

.. code-block:: c

    static int xts_aesni_setkey(struct crypto_skcipher *tfm, const u8 *key,
                                unsigned int keylen)
    {
            struct aesni_xts_ctx *ctx = aes_xts_ctx(tfm);
            int err;

            err = xts_verify_key(tfm, key, keylen);
            if (err)
                    return err;

            keylen /= 2;

            /* first half of xts-key is for crypt */
            err = aes_set_key_common(&ctx->crypt_ctx, key, keylen);
            if (err)
                    return err;

            /* second half of xts-key is for tweak */
            return aes_set_key_common(&ctx->tweak_ctx, key + keylen, keylen);
    }

XTS splits the provided key into two keys: one for data and one for a "tweak".
They are stored in ``ctx->crypt_ctx`` and ``ctx->tweak_ctx``, respectively.

To reach ``ctx``, we need one more getter, :linux:`aes_xts_ctx()
<arch/x86/crypto/aesni-intel_glue.c:226>`:

.. code-block:: c

    static inline struct aesni_xts_ctx *aes_xts_ctx(struct crypto_skcipher *tfm)
    {
            return aes_align_addr(crypto_skcipher_ctx(tfm));
    }

Which uses :linux:`aes_align_addr() <arch/x86/crypto/aesni-intel_glue.c:83>`:

.. code-block:: c

    #define AESNI_ALIGN     16

    static inline void *aes_align_addr(void *addr)
    {
            if (crypto_tfm_ctx_alignment() >= AESNI_ALIGN)
                    return addr;
            return PTR_ALIGN(addr, AESNI_ALIGN);
    }

Implementing that in drgn gets us the key material!

.. code-block:: pycon

    >>> def aes_xts_ctx(tfm):
    ...     AESNI_ALIGN = 16
    ...     mask = AESNI_ALIGN - 1
    ...     ctx = cast("unsigned long", crypto_skcipher_ctx(tfm))
    ...     return cast("struct aesni_xts_ctx *", (ctx + mask) & ~mask)
    ...
    >>> xts_ctx = aes_xts_ctx(cryptd_ctx.child)
    >>> xts_ctx
    *(struct aesni_xts_ctx *)0xffffa3b945dc4030 = {
            .tweak_ctx = (struct crypto_aes_ctx){
                    .key_enc = (u32 [60]){
                            4053857025, 2535432618, 3497512106, 429624542,
                            190965574, 620881567, 2728140233, 1574816406,
                            1642869364, 4143158238, 646209396, 1059050410,
                            2124513770, 1537238901, 4181490364, 2766254122,
                            2225457809, 1918261583, 1423050299, 1808651665,
                            18645611, 1522328862, 2743115682, 123809672, 1080042880,
                            842431695, 1726249716, 220835685, 3602512678,
                            2349145656, 797278618, 686075410, 2304003180,
                            3143774371, 3716565591, 3501188402, 2797609477,
                            717569085, 88128935, 765727669, 1552680193, 3891148194,
                            979927029, 3938949831, 554080963, 197371646, 243473241,
                            589760748, 2460666129, 1967455411, 1328317254,
                            2783648129, 669994703, 741140529, 581956456, 25754500,
                            3453357406, 3096637933, 4156453547, 1381329706,
                    },
                    .key_dec = (u32 [60]){
                            3453357406, 3096637933, 4156453547, 1381329706,
                            1691590497, 1611861415, 2033812690, 3535200077,
                            1503779265, 1400120959, 2713205381, 402136101,
                            2278736107, 79729350, 422218101, 2878299039, 3072023845,
                            181796798, 4073463034, 3057657504, 2722800653,
                            2199015981, 501881779, 2997211882, 893456792,
                            3184435867, 4162446148, 1150040666, 3430456984,
                            559478304, 2667071902, 2941241689, 2504843709,
                            2291118851, 1171735007, 3163937054, 4210330224,
                            3978324152, 3214983102, 834109639, 179351664, 499339966,
                            3445158620, 4181891265, 4283462504, 399827656,
                            1384175366, 2383888249, 3581021031, 393470670,
                            3499860066, 874146333, 3319833674, 3901002144,
                            1163146702, 3700942975, 4053857025, 2535432618,
                            3497512106, 429624542,
                    },
                    .key_length = (u32)32,
            },
            .crypt_ctx = (struct crypto_aes_ctx){
                    .key_enc = (u32 [60]){
                            91118336, 1683438947, 280915620, 1674463119, 3416529787,
                            95371281, 156839573, 539041733, 2748950209, 3348011938,
                            3610309894, 3036590729, 1176448220, 1135635661,
                            1256800856, 1791516061, 4259008143, 978703661,
                            3982827563, 1503367842, 2366333926, 3468365611,
                            2219986291, 4003074286, 3589535297, 4020642668,
                            46334791, 1532531173, 3026313791, 2061167892,
                            4270366823, 269660297, 1916354478, 2644450498,
                            2673614725, 3288632928, 2828270575, 3528005371,
                            750892700, 1020462613, 735205841, 3058517267, 689003158,
                            3977630966, 4257919917, 797156694, 54662090, 1066472927,
                            3047676072, 65707451, 721143597, 3354268635, 1004719636,
                            341928770, 388200584, 682782039, 4002672596, 3984159343,
                            3347232066, 7120537,
                    },
                    .key_dec = (u32 [60]){
                            4002672596, 3984159343, 3347232066, 7120537, 2275767381,
                            3582792214, 728749911, 250810445, 2145441323,
                            3415330885, 1171250799, 717236012, 72947820, 1378379331,
                            4276274497, 631031578, 3286455042, 3027306094,
                            2388528682, 1863317827, 1027747936, 1450278447,
                            2898961154, 3682468443, 2929020077, 2006078828,
                            976160836, 3780245353, 3002856629, 1798524495,
                            4206615853, 2008326489, 523503039, 3641121217,
                            1304255784, 3682533165, 3583917429, 3653810938,
                            2441646946, 2366602356, 2101484483, 3325238398,
                            2495235305, 2529403397, 1276800912, 206997391,
                            1212164504, 478670614, 2260253082, 3144746941,
                            1384732823, 41543404, 2858181789, 1078781983,
                            1142337047, 1422378638, 91118336, 1683438947, 280915620,
                            1674463119,
                    },
                    .key_length = (u32)32,
            },
    }

Extracting the AES Key
----------------------

Since we have a 512-bit key, XTS uses two 256-bit AES keys. You'll notice that
the ``key_enc`` fields above are much larger than that. This is because AES
expands the key into a number of "round keys" using a `"key schedule"
<https://en.wikipedia.org/wiki/AES_key_schedule>`_. Luckily, the first few
round keys are copied directly from the original key.

With that information, we can finally recover the original key::

    >>> def aes_key_from_ctx(ctx):
    ...     words = ctx.key_enc.value_()[:ctx.key_length / 4]
    ...     return b"".join(word.to_bytes(4, "little") for word in words)
    ...
    >>> aes_key_from_ctx(xts_ctx.crypt_ctx).hex()
    '005b6e05633d5764a46ebe108f47ce637b1ba4cb1140af05952e5909c51f2120'
    >>> aes_key_from_ctx(xts_ctx.tweak_ctx).hex()
    '01f3a0f1aaa11f97aacc77d0de8c9b1946e7610b9fe60125c91d9ca296cadd5d'

Which we can double check with cryptsetup:

.. code-block:: console
   :emphasize-lines: 17-20

    # cryptsetup luksDump --dump-master-key /dev/vdb

    WARNING!
    ========
    The header dump with volume key is sensitive information
    that allows access to encrypted partition without a passphrase.
    This dump should be stored encrypted in a safe place.

    Are you sure? (Type 'yes' in capital letters): YES
    Enter passphrase for /dev/vdb: hello
    LUKS header information for /dev/vdb
    Cipher name:    aes
    Cipher mode:    xts-plain64
    Payload offset: 32768
    UUID:           b43cba2c-532b-4491-bbb9-763b55bd7f03
    MK bits:        512
    MK dump:        00 5b 6e 05 63 3d 57 64 a4 6e be 10 8f 47 ce 63
                    7b 1b a4 cb 11 40 af 05 95 2e 59 09 c5 1f 21 20
                    01 f3 a0 f1 aa a1 1f 97 aa cc 77 d0 de 8c 9b 19
                    46 e7 61 0b 9f e6 01 25 c9 1d 9c a2 96 ca dd 5d

Conclusion
----------

Before this, I had almost no knowledge of device mapper or crypto API
internals. drgn makes it easy to explore the kernel and learn how it works.

Note that different system configurations will have different representations
in the crypto API. For example, different ciphers modes will obviously have
different transformations. Even the lack of AES-NI with the same cipher mode
results in different transformation objects.

I converted this case study to the :contrib:`dm_crypt_key.py` script in drgn's
``contrib`` directory. It could be extended to cover other ciphers in the
future.
