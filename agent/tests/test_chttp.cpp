//
// Unit tests for chttp header parsing
//
#include <gtest/gtest.h>
#include "chttp.h"

// Test helper class to access protected/private members
class TestableHttp : public chttp {
public:
    TestableHttp() : chttp() {}

    // Expose the header callback for testing
    static size_t test_header_callback(const std::string& line,
                                        std::unordered_multimap<std::string, std::string>& headers) {
        return header_callback(const_cast<char*>(line.c_str()), 1, line.size(), &headers);
    }

    // Access response headers
    // cppcheck-suppress unusedFunction
    const std::unordered_multimap<std::string, std::string>& get_response_headers() const {
        return m_response_headers;
    }

    // Clear headers for fresh tests
    // cppcheck-suppress unusedFunction
    void clear_headers() {
        m_response_headers.clear();
    }
};

class CHttpHeaderTest : public ::testing::Test {
protected:
    std::unordered_multimap<std::string, std::string> headers;

    void parse_header(const std::string& line) {
        TestableHttp::test_header_callback(line, headers);
    }
};

TEST_F(CHttpHeaderTest, ParsesStandardHeader) {
    parse_header("Content-Type: application/json\r\n");

    auto it = headers.find("content-type");
    ASSERT_NE(it, headers.end());
    EXPECT_EQ(it->second, "application/json");
}

TEST_F(CHttpHeaderTest, ParsesHeaderWithoutSpace) {
    parse_header("X-Custom:value-without-space\r\n");

    auto it = headers.find("x-custom");
    ASSERT_NE(it, headers.end());
    EXPECT_EQ(it->second, "value-without-space");
}

TEST_F(CHttpHeaderTest, ParsesHeaderWithMultipleColons) {
    parse_header("X-Time: 12:34:56\r\n");

    auto it = headers.find("x-time");
    ASSERT_NE(it, headers.end());
    EXPECT_EQ(it->second, "12:34:56");
}

TEST_F(CHttpHeaderTest, IgnoresHttpStatusLine) {
    parse_header("HTTP/1.1 200 OK\r\n");
    EXPECT_TRUE(headers.empty());
}

TEST_F(CHttpHeaderTest, IgnoresEmptyLine) {
    parse_header("\r\n");
    EXPECT_TRUE(headers.empty());
}

TEST_F(CHttpHeaderTest, IgnoresLineWithoutColon) {
    parse_header("Invalid header line\r\n");
    EXPECT_TRUE(headers.empty());
}

TEST_F(CHttpHeaderTest, LowercasesHeaderKey) {
    parse_header("Content-TYPE: text/html\r\n");

    // Should be stored as lowercase
    EXPECT_NE(headers.find("content-type"), headers.end());
    EXPECT_EQ(headers.find("Content-TYPE"), headers.end());
}

TEST_F(CHttpHeaderTest, HandlesMultipleHeaders) {
    parse_header("Content-Type: application/json\r\n");
    parse_header("Content-Length: 1234\r\n");
    parse_header("X-Request-Id: abc123\r\n");

    EXPECT_EQ(headers.size(), 3);
    EXPECT_EQ(headers.find("content-type")->second, "application/json");
    EXPECT_EQ(headers.find("content-length")->second, "1234");
    EXPECT_EQ(headers.find("x-request-id")->second, "abc123");
}

TEST_F(CHttpHeaderTest, HandlesDuplicateHeaders) {
    parse_header("Set-Cookie: cookie1=value1\r\n");
    parse_header("Set-Cookie: cookie2=value2\r\n");

    EXPECT_EQ(headers.count("set-cookie"), 2);
}

TEST_F(CHttpHeaderTest, StripsTrailingNewlines) {
    parse_header("X-Test: value\r\n");

    auto it = headers.find("x-test");
    ASSERT_NE(it, headers.end());
    // Value should not contain \r\n
    EXPECT_EQ(it->second.find('\r'), std::string::npos);
    EXPECT_EQ(it->second.find('\n'), std::string::npos);
}

TEST_F(CHttpHeaderTest, HandlesUnixNewlines) {
    parse_header("X-Test: value\n");

    auto it = headers.find("x-test");
    ASSERT_NE(it, headers.end());
    EXPECT_EQ(it->second, "value");
}

TEST_F(CHttpHeaderTest, EmptyValue) {
    parse_header("X-Empty: \r\n");

    auto it = headers.find("x-empty");
    ASSERT_NE(it, headers.end());
    EXPECT_EQ(it->second, "");
}
