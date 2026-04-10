//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <cstring>

#include "ccert_protocol.h"
#include "clog.h"

ccert_protocol::ccert_protocol(const cert_protocol_t _protocol) : m_protocol(_protocol), m_sbio(nullptr)
{
    std::memset(this->m_buffer, 0, sizeof(this->m_buffer));
}
ccert_protocol::~ccert_protocol()
{
    BIO_free(this->m_sbio);
}
void ccert_protocol::sock(int _sock)
{
    this->m_sbio = BIO_new_socket(_sock, BIO_NOCLOSE);
}
int ccert_protocol::bio_gets(BIO *_bio, const char *_function)
{
    int len = BIO_gets(_bio, this->m_buffer, BUFFER_SIZE);
    if (len <= 0)
    {
        clog::instance().log(LOG_ERROR, "{}: failed on BIO_gets()", _function);
        return len;
    }

    this->m_buffer[len] = '\0';

    return len;
}
int ccert_protocol::bio_read(BIO *_bio, const char *_function)
{
    int len = BIO_read(_bio, this->m_buffer, BUFFER_SIZE - 1);
    if (len <= 0)
    {
        clog::instance().log(LOG_ERROR, "{}: failed on BIO_read()", _function);
        return len;
    }

    this->m_buffer[len] = '\0';

    return len;
}

//
// setup TLS for non-implicit connections
//
bool ccert_protocol::starttls()
{
    switch(this->m_protocol)
    {
        case cert_protocol_t::SMTP_STARTTLS:
        case cert_protocol_t::LMTP_STARTTLS:
        {
            return this->smtp();
        }
        case cert_protocol_t::IMAP_STARTTLS:
        {
            return this->imap();
        }
        case cert_protocol_t::POP3_STARTTLS:
        {
            // cppcheck-suppress knownConditionTrueFalse
            return this->pop3();
        }
        case cert_protocol_t::FTP_STARTTLS:
        {
            return this->ftp();
        }
        case cert_protocol_t::LDAP_STARTTLS:
        {
            return this->ldap();
        }
        case cert_protocol_t::MYSQL:
        {
            return this->mysql();
        }
        case cert_protocol_t::POSTGRESQL:
        {
            return this->postgresql();
        }
        case cert_protocol_t::ORACLE:
        {
            return this->oracle();
        }
        case cert_protocol_t::MSSQL:
        {
            return this->mssql();
        }

        //
        // implicit TLS sockets don't require any additional settings on the socket
        //
        default:
            ;
    }

    return true;
}

//
// ingest off any banners so that we can cleanly disconnect later
//
bool ccert_protocol::init(SSL *_ssl)
{
    switch(this->m_protocol)
    {
        //
        // these protocols have banners
        //
        case cert_protocol_t::SMTPS:
        case cert_protocol_t::IMAPS:
        case cert_protocol_t::POP3S:
        case cert_protocol_t::FTPS:
        {
            SSL_read(_ssl, this->m_buffer, BUFFER_SIZE);
        }
        break;

        //
        // everything else doesn't have a banner
        //
        default:
            ;
    }

    return true;
}

//
// try to shutdown connection gracefully based on their protocol
//
bool ccert_protocol::shutdown(SSL *_ssl)
{
    switch(this->m_protocol)
    {
        case cert_protocol_t::SMTPS:
        case cert_protocol_t::SMTP_STARTTLS:
        case cert_protocol_t::LMTP_STARTTLS:
        case cert_protocol_t::POP3S:
        case cert_protocol_t::POP3_STARTTLS:
        case cert_protocol_t::FTPS:
        case cert_protocol_t::FTP_STARTTLS:
        {
            snprintf(this->m_buffer, sizeof(this->m_buffer), "%s", "QUIT\r\n");

            SSL_write(_ssl, this->m_buffer, strlen(this->m_buffer));
            SSL_read(_ssl, this->m_buffer, BUFFER_SIZE);
        }
        break;
        case cert_protocol_t::IMAPS:
        case cert_protocol_t::IMAP_STARTTLS:
        {
            snprintf(this->m_buffer, sizeof(this->m_buffer), "%s", ". LOGOUT\r\n");

            SSL_write(_ssl, this->m_buffer, strlen(this->m_buffer));
            SSL_read(_ssl, this->m_buffer, BUFFER_SIZE);
        }
        break;
        case cert_protocol_t::LDAPS:
        case cert_protocol_t::LDAP_STARTTLS:
        {
            static const unsigned char unbind_request[] = {

                48, 5, 2, 1, 1, 55, 0
            };

            SSL_write(_ssl, unbind_request, sizeof(unbind_request));
            SSL_read(_ssl, this->m_buffer, BUFFER_SIZE);
        }
        break;
        case cert_protocol_t::MYSQL:
        {
            static const unsigned char quit_request[] = {
                1, 0, 0, 0, 1
            };

            SSL_write(_ssl, quit_request, sizeof(quit_request));
            SSL_read(_ssl, this->m_buffer, BUFFER_SIZE);
        }
        break;
        case cert_protocol_t::POSTGRESQL:
        {
            static const unsigned char terminate_request[] = {
                88, 0, 0, 0, 4
            };

            SSL_write(_ssl, terminate_request, sizeof(terminate_request));
            SSL_read(_ssl, this->m_buffer, BUFFER_SIZE);
        }
        break;
        case cert_protocol_t::ORACLES:
        case cert_protocol_t::ORACLE:
        {
            // TODO
        }
        break;
        case cert_protocol_t::MSSQL:
        {
            // TODO
        }
        break;

        //
        // these protocols don't have specific "log out" commands
        //
        case cert_protocol_t::SIPS:
        case cert_protocol_t::HTTPS:
        default:
        {
            // nothing to do
        }
    }

    return true;
}

//
// SMTP & LMTP
//
bool ccert_protocol::smtp()
{
    //
    // get the system hostname for later
    //
    char hostname[1024];
    std::memset(hostname, 0, 1024);
    gethostname(hostname, 1023);

    BIO *fbio = BIO_new(BIO_f_buffer());
    if (fbio == nullptr)
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::smtp(): failed on BIO_new().");
        return false;
    }
    
    BIO_push(fbio, this->m_sbio);

    //
    // read the initial multi-line response off the buffer
    //
    int len = 0;
    do
    {
        len = this->bio_gets(fbio, "ccert_protocol::smtp()");
        if (len <= 0)
        {
            BIO_pop(fbio);
            BIO_free(fbio);
            return false;
        }

    } while( (len > 3) && (this->m_buffer[3] == '-') );

    //
    // send the hello
    //
    if (this->m_protocol == cert_protocol_t::LMTP_STARTTLS)
    {
        BIO_printf(fbio, "LHLO %s\r\n", hostname);
    } else
    {
        BIO_printf(fbio, "EHLO %s\r\n", hostname);
    }

    BIO_flush(fbio);

    //
    // read multi-line response off the buffer
    //
    bool found_starttls = false;
    do
    {
        len = this->bio_gets(fbio, "ccert_protocol::smtp()");
        if (len <= 0)
        {
            BIO_pop(fbio);
            BIO_free(fbio);
            return false;
        }

        if (strstr(this->m_buffer, "STARTTLS") != nullptr)
        {
            found_starttls = true;
        }

    } while( (len > 3) && (this->m_buffer[3] == '-') );

    BIO_flush(fbio);
    BIO_pop(fbio);
    BIO_free(fbio);

    if (found_starttls == false)
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::smtp(): didn't find STARTTLS under response.");
        return false;
    }

    BIO_printf(this->m_sbio, "STARTTLS\r\n");
    if (this->bio_read(this->m_sbio, "ccert_protocol::smtp()") <= 0)
    {
        return false;
    }

    return true;
}
bool ccert_protocol::imap()
{
    BIO *fbio = BIO_new(BIO_f_buffer());
    if (fbio == nullptr)
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::imap(): failed on BIO_new()");
        return false;
    }

    BIO_push(fbio, this->m_sbio);
    if (this->bio_gets(fbio, "ccert_protocol::imap()") <= 0)
    {
        BIO_pop(fbio);
        BIO_free(fbio);
        return false;
    }

    //
    // STARTTLS requires CAPABILITY
    //
    BIO_printf(fbio, ". CAPABILITY\r\n");
    BIO_flush(fbio);

    //
    // read multi-line response off the buffer
    //
    int len = 0;
    bool found_starttls = false;

    do
    {
        len = this->bio_gets(fbio, "ccert_protocol::imap()");
        if (len <= 0)
        {
            BIO_pop(fbio);
            BIO_free(fbio);
            return false;
        }

        if (strstr(this->m_buffer, "STARTTLS") != nullptr)
        {
            found_starttls = true;
        }

    } while( (len > 3) && (this->m_buffer[0] != '.') );

    BIO_flush(fbio);
    BIO_pop(fbio);
    BIO_free(fbio);

    if (found_starttls == false)
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::imap(): didn't find STARTTLS under CAPABILITY response.");
        return false;
    }

    BIO_printf(this->m_sbio, ". STARTTLS\r\n");
    if (this->bio_read(this->m_sbio, "ccert_protocol::imap()") <= 0)
    {
        return false;
    }

    return true;
}
bool ccert_protocol::pop3()
{
    if (this->bio_read(this->m_sbio, "ccert_protocol::pop3()") <= 0)
    {
        return false;
    }

    BIO_printf(this->m_sbio, "STLS\r\n");
    if (this->bio_read(this->m_sbio, "ccert_protocol::pop3()") <= 0)
    {
        return false;
    }

    return true;
}
bool ccert_protocol::ftp()
{
    BIO *fbio = BIO_new(BIO_f_buffer());
    if (fbio == nullptr)
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::ftp(): failed on BIO_new()");
        return false;
    }

    BIO_push(fbio, this->m_sbio);
    int len = 0;

    //
    // read multi-line response off the buffer
    //
    do
    {
        len = this->bio_gets(fbio, "ccert_protocol::ftp()");
        if (len <= 0)
        {
            BIO_pop(fbio);
            BIO_free(fbio);
            return false;
        }

    } while( (len > 3) && (this->m_buffer[3] == '-') );

    BIO_flush(fbio);
    BIO_pop(fbio);
    BIO_free(fbio);

    BIO_printf(this->m_sbio, "AUTH TLS\r\n");
    if (this->bio_read(this->m_sbio, "ccert_protocol::ftp()") <= 0)
    {
        return false;
    }

    return true;
}
bool ccert_protocol::ldap()
{
    //
    // StartTLS Operation according to RFC 4511
    //
    static char ldap_tls_genconf[] = "asn1=SEQUENCE:LDAPMessage\n"
        "[LDAPMessage]\n"
        "messageID=INTEGER:1\n"
        "extendedReq=EXPLICIT:23A,IMPLICIT:0C,"
        "FORMAT:ASCII,OCT:1.3.6.1.4.1.1466.20037\n";

    BIO *ldapbio = BIO_new(BIO_s_mem());
    if (ldapbio == nullptr)
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::ldap(): failed on BIO_new()");
        return false;
    }
    CONF *conf = NCONF_new(nullptr);
    if (conf == nullptr)
    {
        BIO_free(ldapbio);

        clog::instance().log(LOG_ERROR, "ccert_protocol::ldap(): failed on NCONF_new()");
        return false;
    }

    BIO_puts(ldapbio, ldap_tls_genconf);

    long error = -1;
    if (NCONF_load_bio(conf, ldapbio, &error) <= 0)
    {
        BIO_free(ldapbio);
        NCONF_free(conf);

        clog::instance().log(LOG_ERROR, "ccert_protocol::ldap(): failed on NCONF_load_bio()");
        return false;
    }

    BIO_free(ldapbio);

    char *str = NCONF_get_string(conf, "default", "asn1");
    if (str == nullptr)
    {
        NCONF_free(conf);

        clog::instance().log(LOG_ERROR, "ccert_protocol::ldap(): failed on NCONF_get_string()");
        return false;
    }

    ASN1_TYPE *atype = ASN1_generate_nconf(str, conf);
    if (atype == nullptr)
    {
        NCONF_free(conf);

        clog::instance().log(LOG_ERROR, "ccert_protocol::ldap(): failed on NCONF_get_string()");
        return false;
    }

    NCONF_free(conf);

    BIO_write(this->m_sbio, atype->value.sequence->data, atype->value.sequence->length);
    BIO_flush(this->m_sbio);
    ASN1_TYPE_free(atype);

    if (this->bio_read(this->m_sbio, "ccert_protocol::ldap()") <= 0)
    {
        return false;
    }

    return true;
}
bool ccert_protocol::mysql()
{
    //
    // ssl request packet
    //
    static const unsigned char ssl_req[] = {

        /* payload_length,   sequence_id */
        0x20, 0x00, 0x00, 0x01,
        /* payload */
        /* capability flags, CLIENT_SSL always set */
        0x85, 0xae, 0x7f, 0x00,
        /* max-packet size */
        0x00, 0x00, 0x00, 0x01,
        /* character set */
        0x21,
        /* string[23] reserved (all [0]) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    int len = this->bio_read(this->m_sbio, "ccert_protocol::mysql()");
    if (len <= 0)
    {
        return false;

    } else if (len < 21)
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::mysql(): mysql packet too short");
        return false;

    } else if (len != (4 + this->m_buffer[0] + (this->m_buffer[1] << 8) + (this->m_buffer[2] << 16)))
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::mysql(): mysql packet length doesn't match");
        return false;

    } else if (this->m_buffer[4] != 0xA)
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::mysql(): only protocol version 10 is supported");
        return false;
    }

    int pos = 5;
    for(;;)
    {
        if (pos >= len)
        {
            clog::instance().log(LOG_ERROR, "ccert_protocol::mysql(): can't confirm server version.");
            return false;

        } else if (this->m_buffer[pos++] == '\0')
        {
            break;
        }
    }
    if ((pos + 15) > len)
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::mysql(): handshake packet is too short.");
        return false;
    }

    pos += 12; // skip over conn id[4] + SALT[8]

    if (this->m_buffer[pos++] != '\0')  // verify filler
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::mysql(): handshake packet is broken.");
        return false;
    }

    // capability flags[2]
    if (!((this->m_buffer[pos] + (this->m_buffer[pos + 1] << 8)) & 0x800))
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::mysql(): server does not support SSL");
        return false;
    }

    //
    // send the SSL request
    //
    BIO_write(this->m_sbio, ssl_req, sizeof(ssl_req));
    BIO_flush(this->m_sbio);

    return true;
}
bool ccert_protocol::postgresql()
{
    static const unsigned char ssl_request[] = {

        0, 0, 0, 8,     // length
        4, 210, 22, 47  // SSLRequest
    };

    BIO_write(this->m_sbio, ssl_request, 8);
    BIO_flush(this->m_sbio);

    int len = this->bio_read(this->m_sbio, "ccert_protocol::postgresql()");
    if (len <= 0)
    {
        return false;
    }

    //
    // reply will be a single S if SSL is acceptable
    //
    if ( (len != 1) || (this->m_buffer[0] != 'S') )
    {
        clog::instance().log(LOG_ERROR, "ccert_protocol::postgresql(): failed to init TLS.");
        return false;
    }

    return true;
}
bool ccert_protocol::oracle()
{
    // TODO

    return true;
}
bool ccert_protocol::mssql()
{
    // TODO

    return true;
}
