//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#ifndef DEFINES_H
#define DEFINES_H

//
// how often (in seconds) the agent should check-in for tasks
//
#define AGENT_RUN_INTERVAL 60

//
// the default agent endpoint URL; this is mapped to a global accelerator, so we generally don't need to
// have specific regional endpoint URLs
//
#define AGENT_ENDPOINT_URL "https://agent.generatorlabs.com"

//
// graceful shutdown timeout in seconds; Fargate Spot sends SIGTERM with
// a 120-second deadline before SIGKILL, so we use 90 seconds to leave
// headroom for final cleanup
//
#define SHUTDOWN_TIMEOUT_SECS 90

#define BUFFER_SIZE 2048

enum class agent_mode_t {

    PERSISTENT  = 1,
    SINGLE      = 2
};

enum class cert_result_t : int {

    //
    // network connection related errors
    //
    NETWORK_INTERNAL_FAILURE       = 50100,
    NETWORK_SOCKET_FAILURE         = 50101,
    NETWORK_SOCKET_TIMEOUT         = 50102,
    NETWORK_STARTTLS_FAILURE       = 50103,
    NETWORK_SSL_FAILURE            = 50104,
    NETWORK_IP_LOOKUP_FAILED       = 50105,

    NONE                           = 0
};

enum class task_type_t : int {

    TEST          = 1,
    CONTACT       = 2,
    WEBHOOK       = 3,
    RBL_CHECK     = 4,
    CERT_CHECK    = 5
};

enum class cert_protocol_t : int {

    NONE              = 0,
    HTTPS             = 1,
    SMTPS             = 2,
    SMTP_STARTTLS     = 3,
    IMAPS             = 4,
    IMAP_STARTTLS     = 5,
    POP3S             = 6,
    POP3_STARTTLS     = 7,
    FTPS              = 8,
    FTP_STARTTLS      = 9,
    LDAPS             = 10,
    LDAP_STARTTLS     = 11,
    LMTP_STARTTLS     = 12,
    MYSQL             = 13,
    POSTGRESQL        = 14,
    ORACLES           = 15,
    ORACLE            = 16,
    MSSQL             = 17,
    SIPS              = 18
};

enum class profile_address_type_t : int {

    NONE   = 0,
    DUAL   = 1,
    IPV4   = 2,
    IPV6   = 3
};

#endif // DEFINES_H
