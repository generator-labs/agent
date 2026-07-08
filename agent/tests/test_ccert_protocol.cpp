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

// drive starttls() against a pre-scripted server: the whole server side is
// written to the peer up front (the protocols are lock-step, so the client
// reads it in order), then starttls() runs and its result is returned
static bool run_scripted(cert_protocol_t proto, const std::string& script) {
    int fds[2];
    EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    auto handler = signal(SIGPIPE, SIG_IGN);
    EXPECT_EQ(write(fds[1], script.data(), script.size()), (ssize_t)script.size());

    bool result;
    {
        ccert_protocol p(proto);
        p.sock(fds[0]);
        result = p.starttls();
    }

    close(fds[0]);
    close(fds[1]);
    signal(SIGPIPE, handler);
    return result;
}

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

// reply-code / acceptance validation: a server that advertises STARTTLS but
// then refuses the command must fail, not proceed into a plaintext handshake

TEST(CcertProtocolStarttlsTest, SmtpReturnsTrueWhenStarttlsAccepted) {
    EXPECT_TRUE(run_scripted(cert_protocol_t::SMTP_STARTTLS,
        "220 mail.test ESMTP\r\n250-mail.test\r\n250 STARTTLS\r\n220 Go ahead\r\n"));
}

TEST(CcertProtocolStarttlsTest, SmtpReturnsFalseWhenStarttlsRefused) {
    EXPECT_FALSE(run_scripted(cert_protocol_t::SMTP_STARTTLS,
        "220 mail.test ESMTP\r\n250-mail.test\r\n250 STARTTLS\r\n454 4.7.0 TLS unavailable\r\n"));
}

TEST(CcertProtocolStarttlsTest, SmtpReturnsFalseWhenBannerRejects) {
    EXPECT_FALSE(run_scripted(cert_protocol_t::SMTP_STARTTLS,
        "554 no service here\r\n"));
}

TEST(CcertProtocolStarttlsTest, ImapReturnsTrueWhenStarttlsAccepted) {
    EXPECT_TRUE(run_scripted(cert_protocol_t::IMAP_STARTTLS,
        "* OK ready\r\n* CAPABILITY IMAP4rev1 STARTTLS\r\n. OK done\r\n. OK begin TLS\r\n"));
}

TEST(CcertProtocolStarttlsTest, ImapReturnsFalseWhenStarttlsRefused) {
    EXPECT_FALSE(run_scripted(cert_protocol_t::IMAP_STARTTLS,
        "* OK ready\r\n* CAPABILITY IMAP4rev1 STARTTLS\r\n. OK done\r\n. NO not now\r\n"));
}

TEST(CcertProtocolStarttlsTest, Pop3ReturnsTrueWhenStlsAccepted) {
    EXPECT_TRUE(run_scripted(cert_protocol_t::POP3_STARTTLS,
        "+OK POP3 ready\r\n+OK begin TLS\r\n"));
}

TEST(CcertProtocolStarttlsTest, Pop3ReturnsFalseWhenStlsRefused) {
    EXPECT_FALSE(run_scripted(cert_protocol_t::POP3_STARTTLS,
        "+OK POP3 ready\r\n-ERR no TLS\r\n"));
}

TEST(CcertProtocolStarttlsTest, FtpReturnsTrueWhenAuthTlsAccepted) {
    EXPECT_TRUE(run_scripted(cert_protocol_t::FTP_STARTTLS,
        "220 FTP ready\r\n234 Proceed with negotiation\r\n"));
}

TEST(CcertProtocolStarttlsTest, FtpReturnsFalseWhenAuthTlsRefused) {
    EXPECT_FALSE(run_scripted(cert_protocol_t::FTP_STARTTLS,
        "220 FTP ready\r\n504 TLS not supported\r\n"));
}

// result_code(): an active refusal narrows to PROTOCOL_REJECTED, while a
// server that simply doesn't advertise STARTTLS keeps the generic default

TEST(CcertProtocolStarttlsTest, SmtpRefusalSetsProtocolRejected) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    auto handler = signal(SIGPIPE, SIG_IGN);
    std::string script = "220 mail.test ESMTP\r\n250-mail.test\r\n250 STARTTLS\r\n454 4.7.0 TLS unavailable\r\n";
    ASSERT_EQ(write(fds[1], script.data(), script.size()), (ssize_t)script.size());

    ccert_protocol p(cert_protocol_t::SMTP_STARTTLS);
    p.sock(fds[0]);
    EXPECT_FALSE(p.starttls());
    EXPECT_EQ(p.result_code(), cert_result_t::NETWORK_PROTOCOL_REJECTED);

    close(fds[0]);
    close(fds[1]);
    signal(SIGPIPE, handler);
}

TEST(CcertProtocolStarttlsTest, SmtpNoStarttlsAdvertisedKeepsStarttlsFailure) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    auto handler = signal(SIGPIPE, SIG_IGN);
    std::string script = "220 mail.test ESMTP\r\n250 mail.test\r\n";
    ASSERT_EQ(write(fds[1], script.data(), script.size()), (ssize_t)script.size());

    ccert_protocol p(cert_protocol_t::SMTP_STARTTLS);
    p.sock(fds[0]);
    EXPECT_FALSE(p.starttls());
    EXPECT_EQ(p.result_code(), cert_result_t::NETWORK_STARTTLS_FAILURE);

    close(fds[0]);
    close(fds[1]);
    signal(SIGPIPE, handler);
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

// ldap() StartTLS ExtendedResponse (RFC 4511) parsing — the response is
// pre-loaded on the peer so ldap()'s BIO_read returns it after the request

TEST(CcertProtocolStarttlsTest, LdapReturnsTrueOnResultCodeSuccess) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    auto handler = signal(SIGPIPE, SIG_IGN);

    // SEQUENCE { INTEGER 1, [APPLICATION 24] { ENUMERATED 0, "", "" } }
    const unsigned char ok[] = {
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00
    };
    ASSERT_EQ(write(fds[1], ok, sizeof(ok)), (ssize_t)sizeof(ok));

    ccert_protocol p(cert_protocol_t::LDAP_STARTTLS);
    p.sock(fds[0]);

    EXPECT_TRUE(p.starttls());

    close(fds[1]);
    signal(SIGPIPE, handler);
}

TEST(CcertProtocolStarttlsTest, LdapReturnsFalseOnResultCodeRefused) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    auto handler = signal(SIGPIPE, SIG_IGN);

    // same shape but resultCode 53 (unwilling to perform)
    const unsigned char refused[] = {
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x35, 0x04, 0x00, 0x04, 0x00
    };
    ASSERT_EQ(write(fds[1], refused, sizeof(refused)), (ssize_t)sizeof(refused));

    ccert_protocol p(cert_protocol_t::LDAP_STARTTLS);
    p.sock(fds[0]);

    EXPECT_FALSE(p.starttls());

    close(fds[1]);
    signal(SIGPIPE, handler);
}

TEST(CcertProtocolStarttlsTest, LdapReturnsFalseOnMalformedResponse) {
    int fds[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    auto handler = signal(SIGPIPE, SIG_IGN);

    // truncated LDAPMessage - header claims 12 bytes of content, none follow
    const unsigned char bad[] = { 0x30, 0x0c, 0x02, 0x01, 0x01 };
    ASSERT_EQ(write(fds[1], bad, sizeof(bad)), (ssize_t)sizeof(bad));

    ccert_protocol p(cert_protocol_t::LDAP_STARTTLS);
    p.sock(fds[0]);

    EXPECT_FALSE(p.starttls());

    close(fds[1]);
    signal(SIGPIPE, handler);
}
