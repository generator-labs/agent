//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#ifndef CTASK_CERT_H
#define CTASK_CERT_H

#include <vector>
#include <string>
#include <openssl/x509v3.h>

#include "ctask.h"
#include "defines.h"

class ctask_cert : public ctask
{
    public:
        static constexpr int FETCH_MAX_ATTEMPTS  = 3;
        static constexpr int FETCH_RETRY_DELAY_S = 2;


    friend class TestableCertTask;  // For unit testing

    private:
        int m_monitor;
        int m_event_type;
        cert_protocol_t m_protocol;
        int m_port;
        profile_address_type_t m_address_type;
        int m_profile;
        bool m_valid;
        cert_result_t m_parse_error;

        std::string m_hostname;
        std::string m_sni_hostname;

        json_t *m_ip_override;

    private:
        static bool is_fetch_retryable(const cert_result_t _code);

        profile_address_type_t is_ip(const std::string &_data);

        std::vector<std::string> lookup(const std::string &_hn, const json_t *_ov, const profile_address_type_t _ad);

        std::string pem(const X509 *_cert);
        bool valid_protocol() const;
        bool valid_address_type() const;

    public:
        explicit ctask_cert(const std::string &_id, const json_t *_data);
        ~ctask_cert();

        bool run() override;
};

#endif // CTASK_CERT_H
