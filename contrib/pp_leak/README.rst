=======================
Chasing Page Pool Leaks
=======================

The following scripts were demonstrated in the *Chasing Page Pool Leaks*
talk at netdevconf 0x19. They can be used to inspect inflight pages that have
not yet been returned to the page_pool even after the page_pool was destroyed.

The two ways described in the talk for getting more information on leaked pages
are presented below. Note that some scripts have changed from the talk so
please read below.

Solution 1
==========

One way to find leaked page_pool pages is by scanning all the sockets for SKBs
that are using a leaked page. The leaked page can be in either the linear part
or a fragment in shared_info.

This is the most straightforward way, but it also requires access to the SKBs
which means implementing iteration over many types of sockets.

Example 1.1
------------

The ``scan_tcp_socks.oy`` does just that for TCP sockets. Here's an example output::

    #> ./scan_tcp_socks.py -i eth1
    Found leaked page 0xffffea0000231b80 in linear part of  skb: 0xffff888007289328. sk: 0xffff888007289280

From here the SKB can be investgated in the drgn CLI::

    skb = Object(prog, "struct sk_buff *", address=0xffff888007289328)
    *(struct sk_buff *)0xffff88800731c900 = {
        .next = (struct sk_buff *)0xffff888007289328,
        .prev = (struct sk_buff *)0xffff888007289328,
        .dev = (struct net_device *)0x0,
        .dev_scratch = (unsigned long)0,
    ...
        .tail = (sk_buff_data_t)160,
        .end = (sk_buff_data_t)192,
        .head = (unsigned char *)0xffff888008c6e000 = "", ---> leaking page
        .data = (unsigned char *)0xffff888008c6e082 = "packet data",
    ...

Note that the script can take a long time to run. It is recommended to filter
by interface name via the ``-i`` switch.

Solution 2
==========

The other way to investigate leaked page_pool pages is through tracking back
from the page to the SKB. This involves more guesswork. In broad strokes,
the algorithm can be summarized as below:

1. Scan pages for page_pool pages that are leaked (are linked to a destroyed
   page_pool).
2. Search the kernel memory for references to to the page's virtual address range.
3. Peek memory around the found reference to check if it looks like an SKB.
   This assumes that the leaked page is in the linear area of the SKB.
   If something was found. Stop here. Otherwise go on to next steps.
4. Search the kernel memory for the actual page *pointer*.
   This is looking for the page as a fragment in ``skb_shared_info``. There,
   the actual page pointer is used. What was found *could* be part of ``skb_shared_info``.
5. ``skb_shared_info`` lives in the linear part of the SKB. Search for references to this
   page to find the actual SKB. This is similar to 3.

``ls_pp_leaks.py`` does step 1. ``guess_leaky_skbs.py`` will do steps 2-5.

Here are some examples:

Example 2.1
-----------

The leaked page could be in the linear part of the SKB. First, let's scan the
leaked pages::

    #> ./ls_pp_leaks.py
    Page content:
    ADDRESS           VALUE
    ffff888008c6e000: 0000000000000000
    ffff888008c6e008: 0000000000000000
    ffff888008c6e010: 0000000000000000
    ffff888008c6e018: 0000000000000000
    ffff888008c6e020: 0000000000000000
    ffff888008c6e028: 0000000000000000
    ffff888008c6e030: 0000000000000000
    ffff888008c6e038: 0000000000000000
    ffff888008c6e040: 7dfe573412005452
    ffff888008c6e048: 0045000809f1739e
    ffff888008c6e050: 06400040a3ae5200
    ffff888008c6e058: 01010a010101f687
    ffff888008c6e060: 0000000064980101

Now, let's look for the SKB from the found leak::

    #> ./guess_leaky_skbs.py 0xffffea0000231b80
    Possible skb match at address 0xffff88800731c900

From here the SKB can be printed via the drgn CLI or via the ``--show-skb``
option.

How do you know if the leaked page is in the linear part? You either expect
that SKBs don't have fragments (based on the current configuration) your you
just guess. In any way, it is a good starting point.

If nothing relevant is found, proceed to steps in example 2.2.

Example 2.2
-----------

The leaked page could be in a ``skb_shared_info`` fragment (see
``skb_frag_t``). Once again, let's scan the leaked pages::

    #> ./ls_pp_leaks.py
    Leaked page: 0xffffea00001cea00
    Page content:
    ADDRESS           VALUE
    ffff8880073a8000: 87feffffffffffff
    ffff8880073a8008: 01000608087a2ce1
    ffff8880073a8010: 87fe010004060008
    ffff8880073a8018: 0a020101087a2ce1
    ffff8880073a8020: 0101000000000000
    ffff8880073a8028: 0000000000000102
    ffff8880073a8030: 0000000000000000
    ffff8880073a8038: 0000000000000000
    ffff8880073a8040: 0000000000000000
    ffff8880073a8048: 0000000000000000
    ffff8880073a8050: 0000000000000000
    ffff8880073a8058: 0000000000000000
    ffff8880073a8060: 0000000000000000
    Leaked page: 0xffffea00001cf5c0
    ...

Now we can let the script do the guess work::

    #> ./guess_leaky_skbs.py 0xffffea00001cea00 --as-frag
    Possible skb match at address 0xffff8880047d8a00

You can look at the SKB to see if it makes sense. From there the socket can be
tracked back.

Final Notes
===========

The examples above make the work seem easy. In fact, a lot of guesswork might
be required. Check the options provided by the scripts to dig deeper into
the possibilities.

References
==========

.. _Chasing Page Pool Pages talk https://lore.kernel.org/netdev/20240814075603.05f8b0f5@kernel.org/
.. _Original solution from netdev https://netdevconf.info/0x19/sessions/tutorial/diagnosing-page-pool-leaks.html
