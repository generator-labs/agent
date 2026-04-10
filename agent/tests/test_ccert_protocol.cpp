//
// Unit tests for ccert_protocol
//
#include <gtest/gtest.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include "ccert_protocol.h"

// Test helper to access private members
class TestableProtocol {
public:
    static cert_protocol_t get_protocol(const ccert_protocol& p) {
        return p.m_protocol;
    }
};

// Constructor tests — verify each protocol value is accepted

TEST(CcertProtocolConstructorTest, AcceptsHttps) {
    ccert_protocol p(cert_protocol_t::HTTPS);
    EXPECT_EQ(TestableProtocol::get_protocol(p), cert_protocol_t::HTTPS);
}

TEST(CcertProtocolConstructorTest, AcceptsSmtps) {
    ccert_protocol p(cert_protocol_t::SMTPS);
    EXPECT_EQ(TestableProtocol::get_protocol(p), cert_protocol_t::SMTPS);
}

TEST(CcertProtocolConstructorTest, AcceptsSmtpStarttls) {
    ccert_protocol p(cert_protocol_t::SMTP_STARTTLS);
    EXPECT_EQ(TestableProtocol::get_protocol(p), cert_protocol_t::SMTP_STARTTLS);
}

TEST(CcertProtocolConstructorTest, AcceptsImaps) {
    ccert_protocol p(cert_protocol_t::IMAPS);
    EXPECT_EQ(TestableProtocol::get_protocol(p), cert_protocol_t::IMAPS);
}

TEST(CcertProtocolConstructorTest, AcceptsImapStarttls) {
    ccert_protocol p(cert_protocol_t::IMAP_STARTTLS);
    EXPECT_EQ(TestableProtocol::get_protocol(p), cert_protocol_t::IMAP_STARTTLS);
}

TEST(CcertProtocolConstructorTest, AcceptsPop3s) {
    ccert_protocol p(cert_protocol_t::POP3S);
    EXPECT_EQ(TestableProtocol::get_protocol(p), cert_protocol_t::POP3S);
}

TEST(CcertProtocolConstructorTest, AcceptsFtps) {
    ccert_protocol p(cert_protocol_t::FTPS);
    EXPECT_EQ(TestableProtocol::get_protocol(p), cert_protocol_t::FTPS);
}

TEST(CcertProtocolConstructorTest, AcceptsLdaps) {
    ccert_protocol p(cert_protocol_t::LDAPS);
    EXPECT_EQ(TestableProtocol::get_protocol(p), cert_protocol_t::LDAPS);
}

TEST(CcertProtocolConstructorTest, AcceptsMysql) {
    ccert_protocol p(cert_protocol_t::MYSQL);
    EXPECT_EQ(TestableProtocol::get_protocol(p), cert_protocol_t::MYSQL);
}

TEST(CcertProtocolConstructorTest, AcceptsPostgresql) {
    ccert_protocol p(cert_protocol_t::POSTGRESQL);
    EXPECT_EQ(TestableProtocol::get_protocol(p), cert_protocol_t::POSTGRESQL);
}

TEST(CcertProtocolConstructorTest, AcceptsSips) {
    ccert_protocol p(cert_protocol_t::SIPS);
    EXPECT_EQ(TestableProtocol::get_protocol(p), cert_protocol_t::SIPS);
}

// starttls() tests — implicit TLS protocols hit the default case and return true

TEST(CcertProtocolStarttlsTest, ImplicitHttpsReturnsTrueWithoutIO) {
    ccert_protocol p(cert_protocol_t::HTTPS);
    EXPECT_TRUE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, ImplicitSmtpsReturnsTrueWithoutIO) {
    ccert_protocol p(cert_protocol_t::SMTPS);
    EXPECT_TRUE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, ImplicitImapsReturnsTrueWithoutIO) {
    ccert_protocol p(cert_protocol_t::IMAPS);
    EXPECT_TRUE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, ImplicitPop3sReturnsTrueWithoutIO) {
    ccert_protocol p(cert_protocol_t::POP3S);
    EXPECT_TRUE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, ImplicitFtpsReturnsTrueWithoutIO) {
    ccert_protocol p(cert_protocol_t::FTPS);
    EXPECT_TRUE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, ImplicitLdapsReturnsTrueWithoutIO) {
    ccert_protocol p(cert_protocol_t::LDAPS);
    EXPECT_TRUE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, ImplicitOraclesReturnsTrueWithoutIO) {
    ccert_protocol p(cert_protocol_t::ORACLES);
    EXPECT_TRUE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, ImplicitSipsReturnsTrueWithoutIO) {
    ccert_protocol p(cert_protocol_t::SIPS);
    EXPECT_TRUE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, NoneProtocolReturnsTrueWithoutIO) {
    ccert_protocol p(cert_protocol_t::NONE);
    EXPECT_TRUE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, SmtpReturnsFalseWhenBannerReadFails) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    ccert_protocol p(cert_protocol_t::SMTP_STARTTLS);
    p.sock(fds[0]);
    close(fds[1]);

    EXPECT_FALSE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, ImapReturnsFalseWhenBannerReadFails) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    ccert_protocol p(cert_protocol_t::IMAP_STARTTLS);
    p.sock(fds[0]);
    close(fds[1]);

    EXPECT_FALSE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, Pop3ReturnsFalseWhenBannerReadFails) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    ccert_protocol p(cert_protocol_t::POP3_STARTTLS);
    p.sock(fds[0]);
    close(fds[1]);

    EXPECT_FALSE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, FtpReturnsFalseWhenBannerReadFails) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    ccert_protocol p(cert_protocol_t::FTP_STARTTLS);
    p.sock(fds[0]);
    close(fds[1]);

    EXPECT_FALSE(p.starttls());
}

TEST(CcertProtocolStarttlsTest, LdapReturnsFalseWhenReadFails) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    auto handler = signal(SIGPIPE, SIG_IGN);

    ccert_protocol p(cert_protocol_t::LDAP_STARTTLS);
    p.sock(fds[0]);
    close(fds[1]);

    EXPECT_FALSE(p.starttls());

    signal(SIGPIPE, handler);
}
