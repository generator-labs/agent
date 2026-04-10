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

    private:
        int bio_gets(BIO *_bio, const char *_function);
        int bio_read(BIO *_bio, const char *_function);

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
        bool oracle();
        bool mssql();

    public:
        explicit ccert_protocol(const cert_protocol_t _protocol);
        ~ccert_protocol();

        void sock(int _sock);

        bool starttls();
        bool init(SSL *_ssl);
        bool shutdown(SSL *_ssl);
};

#endif // CCERT_PROTOCOL_H
