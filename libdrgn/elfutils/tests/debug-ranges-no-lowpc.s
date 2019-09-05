        .section .debug_info
.Lcu1_begin:
        .4byte        .Lcu1_end - .Lcu1_start
.Lcu1_start:
        .2byte        3                 /* Version */
        .4byte        .Labbrev1_begin   /* Abbrevs */
        .byte        8                  /* Pointer size */
        .uleb128        2               /* Abbrev (DW_TAG_compile_unit) */
        .4byte        0
.Lcu1_end:
        .section .note.gnu.build-id, "a", %note
        .4byte        4
        .4byte        8
        .4byte        3
        .ascii        "GNU\0"
        .byte        0x01
        .byte        0x02
        .byte        0x03
        .byte        0x04
        .byte        0x05
        .byte        0x06
        .byte        0x07
        .byte        0x08
        .section .debug_abbrev
.Labbrev1_begin:
        .uleb128        2               /* Abbrev start */
        .uleb128        0x11            /* DW_TAG_compile_unit */
        .byte        0                  /* has_children */
        .uleb128        0x55            /* DW_AT_ranges */
        .uleb128        0x06            /* DW_FORM_data4 */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */

	.section .debug_ranges

	.8byte 0xffffffffffffffff
	.8byte 0

	.8byte 1
	.8byte 2

	.8byte 3
	.8byte 4

	.8byte 0
	.8byte 0

