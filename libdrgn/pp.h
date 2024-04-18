// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file
 *
 * Preprocessor utilities.
 *
 * See @ref Preprocessor.
 */

#ifndef DRGN_PP_H
#define DRGN_PP_H

/**
 * @ingroup Internals
 *
 * @defgroup Preprocessor Preprocessor
 *
 * Preprocessor metaprogramming
 *
 * This provides several macros that can be used for preprocessor
 * metaprogramming. It is inspired by the [Boost Preprocessing
 * library](https://www.boost.org/doc/libs/release/libs/preprocessor/doc/index.html).
 *
 * @{
 */

/**
 * Get the number of variadic arguments.
 *
 * ```
 * PP_NARGS(a, b, c) // Expands to 3
 * #define ARGS x, y
 * PP_NARGS(ARGS) // Expands to 2
 * ```
 *
 * An empty argument list is considered to have 0 arguments.
 *
 * ```
 * PP_NARGS() // Expands to 0.
 * ```
 *
 * @remark This depends on the `, ##__VA_ARGS__` GNU C extension. `__VA_OPT__`
 * could be used instead, but it is only supported since GCC 8 (released in
 * 2018) and Clang 12 (released in 2021).
 *
 * @hideinitializer
 */
#define PP_NARGS(...) PP_NARGS_I(__VA_ARGS__)
/** @cond */
// The extra layer of indirection ensures that arguments are expanded.
#define PP_NARGS_I(...) PP_NARGS_II(, ##__VA_ARGS__, 64, 63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define PP_NARGS_II(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, _62, _63, _64, N, ...) N
/** @endcond */

/**
 * Overload a macro based on the number of arguments.
 *
 * This expands to @p prefix concatenated with the number of arguments (as
 * determined by @ref PP_NARGS()). Use it like so:
 *
 * ```
 * #define DEFINE_ARRAY(...) PP_OVERLOAD(DEFINE_ARRAY_I, __VA_ARGS__)(__VA_ARGS__)
 * #define DEFINE_ARRAY_I2(name, type) DEFINE_ARRAY_I3(a, b, DEFAULT_ARRAY_SIZE)
 * #define DEFINE_ARRAY_I3(name, type, size) type name[size]
 * #define DEFAULT_ARRAY_SIZE 5
 *
 * DEFINE_ARRAY(int, several); // Expands to int several[5];
 * DEFINE_ARRAY(int, couple, 2); // Expands to int couple[2];
 * ```
 *
 * @hideinitializer
 */
#define PP_OVERLOAD(prefix, ...) PP_OVERLOAD_CAT_I(prefix, PP_NARGS(__VA_ARGS__))
/** @cond */
#define PP_OVERLOAD_CAT_I(a, b) PP_OVERLOAD_CAT_II(a, b)
#define PP_OVERLOAD_CAT_II(a, b) a##b
/** @endcond */

/**
 * Expand and concatenate arguments.
 *
 * This expands each argument and then joins them with the `##` operator.
 * `PP_CAT` takes two arguments, `PP_CAT3` takes three, `PP_CAT4` takes four,
 * etc.
 *
 * ```
 * #define a foo
 * #define b bar
 * PP_CAT(a, b) // Expands to foobar
 * ```
 *
 * Intermediate results are not expanded:
 * ```
 * #define HELLO oops
 * PP_CAT3(HELL, O, WORLD) // Expands to HELLOWORLD, _not_ oopsWORLD
 * ```
 *
 * All possible intermediate results must be valid preprocessing tokens:
 * ```
 * PP_CAT3(1e, +, 3) // Undefined because +3 is not a valid preprocessing token
 * ```
 *
 * @hideinitializer
 */
#define PP_CAT(_0, _1) PP_CAT_I2(_0, _1)
#define PP_CAT3(_0, _1, _2) PP_CAT_I3(_0, _1, _2)
#define PP_CAT4(_0, _1, _2, _3) PP_CAT_I4(_0, _1, _2, _3)
#define PP_CAT5(_0, _1, _2, _3, _4) PP_CAT_I5(_0, _1, _2, _3, _4)
#define PP_CAT6(_0, _1, _2, _3, _4, _5) PP_CAT_I6(_0, _1, _2, _3, _4, _5)
#define PP_CAT7(_0, _1, _2, _3, _4, _5, _6) PP_CAT_I7(_0, _1, _2, _3, _4, _5, _6)
#define PP_CAT8(_0, _1, _2, _3, _4, _5, _6, _7) PP_CAT_I8(_0, _1, _2, _3, _4, _5, _6, _7)
/** @cond */
#define PP_CAT_I2(_0, _1) _0##_1
#define PP_CAT_I3(_0, _1, _2) _0##_1##_2
#define PP_CAT_I4(_0, _1, _2, _3) _0##_1##_2##_3
#define PP_CAT_I5(_0, _1, _2, _3, _4) _0##_1##_2##_3##_4
#define PP_CAT_I6(_0, _1, _2, _3, _4, _5) _0##_1##_2##_3##_4##_5
#define PP_CAT_I7(_0, _1, _2, _3, _4, _5, _6) _0##_1##_2##_3##_4##_5##_6
#define PP_CAT_I8(_0, _1, _2, _3, _4, _5, _6, _7) _0##_1##_2##_3##_4##_5##_6##_7
/** @endcond */

/**
 * Call a macro on each variable argument.
 *
 * ```
 * #define add_string(arg, x) x arg
 * PP_MAP(add_string, "\n", "abc", "def") // Expands to "abc" "\n" "def" "\n"
 * ```
 *
 * @param[in] func Macro taking @p arg and the next variable argument.
 * @param[in] arg First argument to pass to @p func.
 *
 * @hideinitializer
 */
#define PP_MAP(func, arg, ...) PP_OVERLOAD(PP_MAP_I, __VA_ARGS__)(func, arg, __VA_ARGS__)
/** @cond */
#define PP_MAP_I64(func, arg, x, ...) func(arg, x) PP_MAP_I63(func, arg, __VA_ARGS__)
#define PP_MAP_I63(func, arg, x, ...) func(arg, x) PP_MAP_I62(func, arg, __VA_ARGS__)
#define PP_MAP_I62(func, arg, x, ...) func(arg, x) PP_MAP_I61(func, arg, __VA_ARGS__)
#define PP_MAP_I61(func, arg, x, ...) func(arg, x) PP_MAP_I60(func, arg, __VA_ARGS__)
#define PP_MAP_I60(func, arg, x, ...) func(arg, x) PP_MAP_I59(func, arg, __VA_ARGS__)
#define PP_MAP_I59(func, arg, x, ...) func(arg, x) PP_MAP_I58(func, arg, __VA_ARGS__)
#define PP_MAP_I58(func, arg, x, ...) func(arg, x) PP_MAP_I57(func, arg, __VA_ARGS__)
#define PP_MAP_I57(func, arg, x, ...) func(arg, x) PP_MAP_I56(func, arg, __VA_ARGS__)
#define PP_MAP_I56(func, arg, x, ...) func(arg, x) PP_MAP_I55(func, arg, __VA_ARGS__)
#define PP_MAP_I55(func, arg, x, ...) func(arg, x) PP_MAP_I54(func, arg, __VA_ARGS__)
#define PP_MAP_I54(func, arg, x, ...) func(arg, x) PP_MAP_I53(func, arg, __VA_ARGS__)
#define PP_MAP_I53(func, arg, x, ...) func(arg, x) PP_MAP_I52(func, arg, __VA_ARGS__)
#define PP_MAP_I52(func, arg, x, ...) func(arg, x) PP_MAP_I51(func, arg, __VA_ARGS__)
#define PP_MAP_I51(func, arg, x, ...) func(arg, x) PP_MAP_I50(func, arg, __VA_ARGS__)
#define PP_MAP_I50(func, arg, x, ...) func(arg, x) PP_MAP_I49(func, arg, __VA_ARGS__)
#define PP_MAP_I49(func, arg, x, ...) func(arg, x) PP_MAP_I48(func, arg, __VA_ARGS__)
#define PP_MAP_I48(func, arg, x, ...) func(arg, x) PP_MAP_I47(func, arg, __VA_ARGS__)
#define PP_MAP_I47(func, arg, x, ...) func(arg, x) PP_MAP_I46(func, arg, __VA_ARGS__)
#define PP_MAP_I46(func, arg, x, ...) func(arg, x) PP_MAP_I45(func, arg, __VA_ARGS__)
#define PP_MAP_I45(func, arg, x, ...) func(arg, x) PP_MAP_I44(func, arg, __VA_ARGS__)
#define PP_MAP_I44(func, arg, x, ...) func(arg, x) PP_MAP_I43(func, arg, __VA_ARGS__)
#define PP_MAP_I43(func, arg, x, ...) func(arg, x) PP_MAP_I42(func, arg, __VA_ARGS__)
#define PP_MAP_I42(func, arg, x, ...) func(arg, x) PP_MAP_I41(func, arg, __VA_ARGS__)
#define PP_MAP_I41(func, arg, x, ...) func(arg, x) PP_MAP_I40(func, arg, __VA_ARGS__)
#define PP_MAP_I40(func, arg, x, ...) func(arg, x) PP_MAP_I39(func, arg, __VA_ARGS__)
#define PP_MAP_I39(func, arg, x, ...) func(arg, x) PP_MAP_I38(func, arg, __VA_ARGS__)
#define PP_MAP_I38(func, arg, x, ...) func(arg, x) PP_MAP_I37(func, arg, __VA_ARGS__)
#define PP_MAP_I37(func, arg, x, ...) func(arg, x) PP_MAP_I36(func, arg, __VA_ARGS__)
#define PP_MAP_I36(func, arg, x, ...) func(arg, x) PP_MAP_I35(func, arg, __VA_ARGS__)
#define PP_MAP_I35(func, arg, x, ...) func(arg, x) PP_MAP_I34(func, arg, __VA_ARGS__)
#define PP_MAP_I34(func, arg, x, ...) func(arg, x) PP_MAP_I33(func, arg, __VA_ARGS__)
#define PP_MAP_I33(func, arg, x, ...) func(arg, x) PP_MAP_I32(func, arg, __VA_ARGS__)
#define PP_MAP_I32(func, arg, x, ...) func(arg, x) PP_MAP_I31(func, arg, __VA_ARGS__)
#define PP_MAP_I31(func, arg, x, ...) func(arg, x) PP_MAP_I30(func, arg, __VA_ARGS__)
#define PP_MAP_I30(func, arg, x, ...) func(arg, x) PP_MAP_I29(func, arg, __VA_ARGS__)
#define PP_MAP_I29(func, arg, x, ...) func(arg, x) PP_MAP_I28(func, arg, __VA_ARGS__)
#define PP_MAP_I28(func, arg, x, ...) func(arg, x) PP_MAP_I27(func, arg, __VA_ARGS__)
#define PP_MAP_I27(func, arg, x, ...) func(arg, x) PP_MAP_I26(func, arg, __VA_ARGS__)
#define PP_MAP_I26(func, arg, x, ...) func(arg, x) PP_MAP_I25(func, arg, __VA_ARGS__)
#define PP_MAP_I25(func, arg, x, ...) func(arg, x) PP_MAP_I24(func, arg, __VA_ARGS__)
#define PP_MAP_I24(func, arg, x, ...) func(arg, x) PP_MAP_I23(func, arg, __VA_ARGS__)
#define PP_MAP_I23(func, arg, x, ...) func(arg, x) PP_MAP_I22(func, arg, __VA_ARGS__)
#define PP_MAP_I22(func, arg, x, ...) func(arg, x) PP_MAP_I21(func, arg, __VA_ARGS__)
#define PP_MAP_I21(func, arg, x, ...) func(arg, x) PP_MAP_I20(func, arg, __VA_ARGS__)
#define PP_MAP_I20(func, arg, x, ...) func(arg, x) PP_MAP_I19(func, arg, __VA_ARGS__)
#define PP_MAP_I19(func, arg, x, ...) func(arg, x) PP_MAP_I18(func, arg, __VA_ARGS__)
#define PP_MAP_I18(func, arg, x, ...) func(arg, x) PP_MAP_I17(func, arg, __VA_ARGS__)
#define PP_MAP_I17(func, arg, x, ...) func(arg, x) PP_MAP_I16(func, arg, __VA_ARGS__)
#define PP_MAP_I16(func, arg, x, ...) func(arg, x) PP_MAP_I15(func, arg, __VA_ARGS__)
#define PP_MAP_I15(func, arg, x, ...) func(arg, x) PP_MAP_I14(func, arg, __VA_ARGS__)
#define PP_MAP_I14(func, arg, x, ...) func(arg, x) PP_MAP_I13(func, arg, __VA_ARGS__)
#define PP_MAP_I13(func, arg, x, ...) func(arg, x) PP_MAP_I12(func, arg, __VA_ARGS__)
#define PP_MAP_I12(func, arg, x, ...) func(arg, x) PP_MAP_I11(func, arg, __VA_ARGS__)
#define PP_MAP_I11(func, arg, x, ...) func(arg, x) PP_MAP_I10(func, arg, __VA_ARGS__)
#define PP_MAP_I10(func, arg, x, ...) func(arg, x) PP_MAP_I9(func, arg, __VA_ARGS__)
#define PP_MAP_I9(func, arg, x, ...) func(arg, x) PP_MAP_I8(func, arg, __VA_ARGS__)
#define PP_MAP_I8(func, arg, x, ...) func(arg, x) PP_MAP_I7(func, arg, __VA_ARGS__)
#define PP_MAP_I7(func, arg, x, ...) func(arg, x) PP_MAP_I6(func, arg, __VA_ARGS__)
#define PP_MAP_I6(func, arg, x, ...) func(arg, x) PP_MAP_I5(func, arg, __VA_ARGS__)
#define PP_MAP_I5(func, arg, x, ...) func(arg, x) PP_MAP_I4(func, arg, __VA_ARGS__)
#define PP_MAP_I4(func, arg, x, ...) func(arg, x) PP_MAP_I3(func, arg, __VA_ARGS__)
#define PP_MAP_I3(func, arg, x, ...) func(arg, x) PP_MAP_I2(func, arg, __VA_ARGS__)
#define PP_MAP_I2(func, arg, x, ...) func(arg, x) PP_MAP_I1(func, arg, __VA_ARGS__)
#define PP_MAP_I1(func, arg, x) func(arg, x)
#define PP_MAP_I0(func, arg, x)
/** @endcond */

/**
 * Create a unique name.
 *
 * This can be used to avoid name collisions and shadowing in macros that define
 * local variables.
 *
 * ```
 * #define SWAP(a, b) SWAP_I(a, b, PP_UNIQUE(tmp))
 * #define SWAP_I(a, b, tmp) do { typeof(a) tmp = (a); (a) = (b); (b) = tmp; } while (0)
 * ```
 *
 * @param[in] prefix Prefix for unique name. This makes the created name more
 * recognizable in compiler diagnostics and debuggers. This is not expanded.
 *
 * @hideinitializer
 */
#define PP_UNIQUE(prefix) PP_CAT(prefix##__PP_UNIQUE_, __COUNTER__)

/** @} */

#endif /* DRGN_PP_H */
