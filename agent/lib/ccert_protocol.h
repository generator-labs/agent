//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#ifndef CCERT_PROTOCOL_H
#define CCERT_PROTOCOL_H

#include "defines.h"

class ccert_protocol
{
    friend class TestableProtocol;

    private:
        cert_protocol_t m_protocol;
        BIO *m_sbio;
        char m_buffer[BUFFER_SIZE];

        //
        // the result code describing why starttls() failed; defaults to a
        // generic STARTTLS failure and is narrowed to a protocol-rejection
        // code when the server actively refuses the pre-TLS negotiation
        //
        cert_result_t m_result_code;

    private:
        int bio_gets(BIO *_bio, const char *_function);
        int bio_read(BIO *_bio, const char *_function);

        //
        // parse the leading 3-digit reply code from an SMTP/FTP response line;
        // returns -1 if the line doesn't begin with a numeric code
        //
        static int reply_code(const char *_line, int _len);

        //
        // "STARTTLS" functions
        //
        bool smtp();
        bool imap();
        bool pop3();
        bool ftp();
        bool ldap();
        bool mysql();
        bool postgresql();
        static bool oracle();
        static bool mssql();

    public:
        explicit ccert_protocol(const cert_protocol_t _protocol);
        ~ccert_protocol();

        void sock(int _sock);

        bool starttls();
        bool init(SSL *_ssl);
        bool shutdown(SSL *_ssl);

        //
        // the result code describing the most recent starttls() failure
        //
        cert_result_t result_code() const { return this->m_result_code; }
};

#endif // CCERT_PROTOCOL_H
