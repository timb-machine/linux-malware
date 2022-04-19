/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.
// This is a set of helper macros simplify all the nested if statements in code.

#pragma once

// checkpatch-ignore: MACRO_WITH_FLOW_CONTROL
#define XSET      { xcode = val; }
#define XSET_MSG  { xcode = val; TRACE(msg); }
#define MSG       { TRACE(msg); }

#define TRY(x)                                             C_TEST(DEFAULT, (x), {},                           {})
#define TRY_DO(x, stmt)                                    C_TEST(DEFAULT, (x), {},                           stmt)
#define TRY_DO_MSG(x, stmt, msg...)                        C_TEST(DEFAULT, (x), { TRACE(msg); },              stmt)
#define TRY_MSG(x, msg...)                                 C_TEST(DEFAULT, (x), { TRACE(msg); },              {})
#define TRY_SET(x, val)                                    C_TEST(DEFAULT, (x), { xcode = val; },             {})
#define TRY_SET_DO(x, val, stmt)                           C_TEST(DEFAULT, (x), { xcode = val; },             stmt)
#define TRY_SET_DO_MSG(x, val, stmt)                       C_TEST(DEFAULT, (x), { xcode = val; },             stmt)
#define TRY_SET_MSG(x, val, msg...)                        C_TEST(DEFAULT, (x), { xcode = val; TRACE(msg); }, {})

#define TRY_STEP(step, x)                                  C_TEST(step,    (x), {},                           {})
#define TRY_STEP_DO(step, x, stmt)                         C_TEST(step,    (x), {},                           stmt)
#define TRY_STEP_DO_MSG(step, x, stmt, msg...)             C_TEST(step,    (x), { TRACE(msg); },              stmt)
#define TRY_STEP_MSG(step, x, msg...)                      C_TEST(step,    (x), { TRACE(msg); },              {})
#define TRY_STEP_SET(step, x, val)                         C_TEST(step,    (x), { xcode = val; },             {})
#define TRY_STEP_SET_DO(step, x, val, stmt)                C_TEST(step,    (x), { xcode = val; },             stmt)
#define TRY_STEP_SET_DO_MSG(step, x, val, stmt, msg...)    C_TEST(step,    (x), { xcode = val; TRACE(msg); }, stmt)
#define TRY_STEP_SET_MSG(step, x, val, msg...)             C_TEST(step,    (x), { TRACE(msg); },              {})

#define CANCEL(x, val)                                     R_TEST((x), {},                { return val; })
#define CANCEL_MSG(x, val, msg...)                         R_TEST((x), { TRACE(msg); },   { return val; })
#define CANCEL_DO(x, val, stmt)                            R_TEST((x), stmt,              { return val; })
#define CANCEL_VOID(x)                                     R_TEST((x), {},                { return; })
#define CANCEL_VOID_DO(x, stmt)                            R_TEST((x), stmt,              { return; })
#define CANCEL_VOID_MSG(x, msg...)                         R_TEST((x), { TRACE(msg); },   { return; })

#define C_TEST(step, x, stmt1, stmt2) do {  \
    if (!(x)) {                             \
        stmt1                               \
        stmt2                               \
        goto CATCH_##step;                  \
    }                                       \
} while (0)

#define R_TEST(x, stmt1, stmt2) do { \
    if (!(x)) {                      \
        stmt1                        \
        stmt2                        \
    }                                \
} while (0)

#define IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(counter, stmt) \
do { \
    int64_t count = atomic64_dec_return(counter); \
    WARN(count < 0, "Decremented past zero: %lld", count); \
    if (count == 0) { \
        stmt \
    } \
} while (false)

#define IF_ATOMIC64_DEC_AND_TEST__TRY_NEG(counter, stmt, should_warn) \
do { \
    int64_t count = atomic64_dec_return(counter); \
    WARN(should_warn && count < 0, "Decremented past zero: %lld", count); \
    TRY(count >= 0); \
    if (count == 0) { \
        stmt \
    } \
} while (false)

#define ATOMIC64_DEC__CHECK_NEG(counter) IF_ATOMIC64_DEC_AND_TEST__CHECK_NEG(counter, {})
