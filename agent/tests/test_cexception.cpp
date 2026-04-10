//
// Unit tests for cexception
//
#include <gtest/gtest.h>
#include "cexception.h"

TEST(CExceptionTest, BasicMessage) {
    cexception ex("simple error message");
    EXPECT_STREQ(ex.what(), "simple error message");
}

TEST(CExceptionTest, FormattedMessageWithInt) {
    cexception ex("error code: {}", 42);
    EXPECT_STREQ(ex.what(), "error code: 42");
}

TEST(CExceptionTest, FormattedMessageWithString) {
    cexception ex("file not found: {}", "config.json");
    EXPECT_STREQ(ex.what(), "file not found: config.json");
}

TEST(CExceptionTest, FormattedMessageMultipleArgs) {
    cexception ex("error {} at line {}", "syntax", 123);
    EXPECT_STREQ(ex.what(), "error syntax at line 123");
}

TEST(CExceptionTest, EmptyMessage) {
    cexception ex("");
    EXPECT_STREQ(ex.what(), "");
}

TEST(CExceptionTest, ThrowAndCatch) {
    EXPECT_THROW({
        throw cexception("test error");
    }, cexception);
}

TEST(CExceptionTest, CatchAsStdException) {
    try {
        throw cexception("caught as std::exception");
    } catch (const std::exception& e) {
        EXPECT_STREQ(e.what(), "caught as std::exception");
    }
}
