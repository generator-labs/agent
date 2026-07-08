//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <poll.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <cstring>
#include <iomanip>
#include <thread>
#include <random>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ctask_cert.h"
#include "ccert_protocol.h"
#include "cagent.h"
#include "clog.h"
#include "cexception.h"
#include "defines.h"

ctask_cert::ctask_cert(const std::string &_id, const json_t *_data) : m_monitor(-1), m_event_type(-1), m_protocol(cert_protocol_t::NONE), m_port(-1),
    m_address_type(profile_address_type_t::NONE), m_profile(-1), m_valid(true), m_parse_error(cert_result_t::NONE), m_hostname(), m_sni_hostname(), m_ip_override(nullptr)
{
    const char *key;
    json_t *value;

    this->m_id = _id;

    json_object_foreach(const_cast<json_t*>(_data), key, value)
    {
        if (strcmp(key, "monitor") == 0)
        {
            if (json_is_integer(value) != 0)
            {
                this->m_monitor = json_integer_value(value);
            } else
            {
                this->m_valid = false;
                this->m_parse_error = cert_result_t::NETWORK_INTERNAL_FAILURE;
                clog::instance().log(LOG_ERROR, "ctask_cert::ctask_cert(): invalid 'monitor' value.");
            }

        } else if (strcmp(key, "event_type") == 0)
        {
            if (json_is_integer(value) != 0)
            {
                this->m_event_type = json_integer_value(value);
            } else
            {
                this->m_valid = false;
                this->m_parse_error = cert_result_t::NETWORK_INTERNAL_FAILURE;
                clog::instance().log(LOG_ERROR, "ctask_cert::ctask_cert(): invalid 'event_type' value.");
            }

        } else if (strcmp(key, "protocol") == 0)
        {
            if (json_is_integer(value) != 0)
            {
                this->m_protocol = static_cast<cert_protocol_t>(json_integer_value(value));
            } else
            {
                this->m_valid = false;
                this->m_parse_error = cert_result_t::NETWORK_INTERNAL_FAILURE;
                clog::instance().log(LOG_ERROR, "ctask_cert::ctask_cert(): invalid 'protocol' value.");
            }

        } else if (strcmp(key, "port") == 0)
        {
            if (json_is_integer(value) != 0)
            {
                this->m_port = json_integer_value(value);
            } else
            {
                this->m_valid = false;
                this->m_parse_error = cert_result_t::NETWORK_INTERNAL_FAILURE;
                clog::instance().log(LOG_ERROR, "ctask_cert::ctask_cert(): invalid 'port' value.");
            }

        } else if (strcmp(key, "address_type") == 0)
        {
            if (json_is_integer(value) != 0)
            {
                this->m_address_type = static_cast<profile_address_type_t>(json_integer_value(value));
            } else
            {
                this->m_valid = false;
                this->m_parse_error = cert_result_t::NETWORK_INTERNAL_FAILURE;
                clog::instance().log(LOG_ERROR, "ctask_cert::ctask_cert(): invalid 'address_type' value.");
            }

        } else if (strcmp(key, "profile") == 0)
        {
            if (json_is_integer(value) != 0)
            {
                this->m_profile = json_integer_value(value);
            } else
            {
                this->m_valid = false;
                this->m_parse_error = cert_result_t::NETWORK_INTERNAL_FAILURE;
                clog::instance().log(LOG_ERROR, "ctask_cert::ctask_cert(): invalid 'profile' value.");
            }

        } else if (strcmp(key, "hostname") == 0)
        {
            if (json_is_string(value) != 0)
            {
                this->m_hostname = json_string_value(value);
            } else
            {
                this->m_valid = false;
                this->m_parse_error = cert_result_t::NETWORK_INTERNAL_FAILURE;
                clog::instance().log(LOG_ERROR, "ctask_cert::ctask_cert(): invalid 'hostname' value.");
            }

        } else if (strcmp(key, "sni_hostname") == 0)
        {
            if (json_is_string(value) != 0)
            {
                this->m_sni_hostname = json_string_value(value);
            } else
            {
                this->m_valid = false;
                this->m_parse_error = cert_result_t::NETWORK_INTERNAL_FAILURE;
                clog::instance().log(LOG_ERROR, "ctask_cert::ctask_cert(): invalid 'sni_hostname' value.");
            }

        } else if (strcmp(key, "ip_override") == 0)
        {
            if (json_is_array(value) != 0)
            {
                this->m_ip_override = value;
            } else
            {
                this->m_valid = false;
                this->m_parse_error = cert_result_t::NETWORK_INTERNAL_FAILURE;
                clog::instance().log(LOG_ERROR, "ctask_cert::ctask_cert(): invalid 'ip_override' value.");
            }

        } else
        {
            clog::instance().log(LOG_NOTICE, "ctask_cert::ctask_cert(): ignoring undefined key '{}'", key);
        }
    }
}
ctask_cert::~ctask_cert()
{
}
bool ctask_cert::is_fetch_retryable(const cert_result_t _code)
{
    return (_code == cert_result_t::NETWORK_SOCKET_FAILURE   ||
            _code == cert_result_t::NETWORK_SOCKET_TIMEOUT   ||
            _code == cert_result_t::NETWORK_STARTTLS_FAILURE ||
            _code == cert_result_t::NETWORK_SSL_FAILURE      ||
            _code == cert_result_t::NETWORK_PROTOCOL_REJECTED);
}
int ctask_cert::retry_delay_ms(const int _attempt)
{
    //
    // exponential delay: base * 2^(attempt-1), capped
    //
    int delay = FETCH_RETRY_BASE_DELAY_MS << (_attempt - 1);
    if ( (delay > FETCH_RETRY_MAX_DELAY_MS) || (delay <= 0) )
    {
        delay = FETCH_RETRY_MAX_DELAY_MS;
    }

    //
    // equal jitter: sleep a random value in [delay/2, delay] so retries from
    // our shared source IP don't fire in lockstep against a rate-limiting server
    //
    static thread_local std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<int> distribution(delay / 2, delay);

    return distribution(generator);
}
bool ctask_cert::run()
{
    clog::instance().log(LOG_NOTICE, "running certificate check task id={} host={}:{}", this->m_id, this->m_hostname, this->m_port);

    //
    // the list of certificate "stacks" to return
    //
    json_t *stack_list = json_array();

    //
    // "global" level errors
    //
    json_t *stack_error_codes = json_array();

    //
    // the list of resolved IP addresses to connect to
    //
    std::vector<std::string> ips;

    //
    // if we don't have enough settings to process the request, then fail right away
    //
    if ( (this->m_valid == false) || (this->m_id.length() == 0) || (this->m_protocol == cert_protocol_t::NONE) || (this->m_port <= 0) ||
         (this->m_port > 65535) || (this->m_address_type == profile_address_type_t::NONE) || (this->m_hostname.length() == 0) ||
         (this->valid_protocol() == false) || (this->valid_address_type() == false) )
    {
        json_array_append_new(stack_error_codes, json_integer(static_cast<int>((this->m_parse_error == cert_result_t::NONE) ? cert_result_t::NETWORK_INTERNAL_FAILURE : this->m_parse_error)));
        goto finished;
    }

    //
    // look up and loop through the IPs
    //
    ips = this->lookup(this->m_hostname, this->m_ip_override, this->m_address_type);
    if (ips.size() == 0)
    {
        json_array_append_new(stack_error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_IP_LOOKUP_FAILED)));
        goto finished;
    }

    for(const std::string &ip : ips)
    {
        //
        // the stack of certs for this check
        //
        json_t *stack = json_object();
        json_object_set_new(stack, "address", json_string(ip.c_str()));

        //
        // processing error codes
        //
        json_t *error_codes = json_array();

        for (int attempt = 0; attempt < FETCH_MAX_ATTEMPTS; attempt++)
        {
            //
            // openssl pointers - fresh on each attempt
            //
            SSL_CTX *ctx            = nullptr;
            SSL *ssl                = nullptr;
            STACK_OF(X509) *chain   = nullptr;

            //
            // socket timeout struct
            //
            struct timeval tv = { 10, 0 };

            //
            // based on the protocol, we may need to issue STARTTLS commands on the socket before we continue
            //
            ccert_protocol protocol(this->m_protocol);

            struct pollfd pfd = {};
            int flags = 0;
            int ret = 0;
            int family = -1;
            int sock = -1;
            socklen_t socket_error_length = sizeof(ret);

            //
            // tracks whether the failure was a transient connection error eligible for retry
            //
            cert_result_t last_retryable = cert_result_t::NONE;

            //
            // setup the ipv4 or ipv6 socket
            //
            struct sockaddr_storage addr;
            std::memset(&addr, 0, sizeof(addr));

            switch(this->is_ip(ip))
            {
                case profile_address_type_t::IPV4:
                {
                    family = AF_INET;
                    auto* a4 = reinterpret_cast<struct sockaddr_in*>(&addr);
                    a4->sin_family = AF_INET;
                    a4->sin_port = htons(this->m_port);

                    inet_pton(AF_INET, ip.c_str(), &a4->sin_addr);
                }
                break;
                case profile_address_type_t::IPV6:
                {
                    family = AF_INET6;
                    auto* a6 = reinterpret_cast<struct sockaddr_in6*>(&addr);
                    a6->sin6_family = AF_INET6;
                    a6->sin6_port = htons(this->m_port);

                    inet_pton(AF_INET6, ip.c_str(), &a6->sin6_addr);
                }
                break;
                case profile_address_type_t::NONE:
                default:
                {
                    json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_FAILURE)));

                    clog::instance().log(LOG_WARN, "ctask_cert::run(): invalid IP address provided: '{}' {}", ip, strerror(errno));
                    goto attempt_cleanup;
                }
            }

            sock = socket(family, SOCK_STREAM, 0);
            if (sock == -1)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed to create socket() {}:{} - {}", ip, this->m_port, strerror(errno));
                goto attempt_cleanup;
            }

            //
            // set the socket non-blocking so we can timeout properly
            //
            flags = fcntl(sock, F_GETFL, 0);
            if (flags == -1)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on fcntl(F_GETFL) for {}:{} - {}", ip, this->m_port, strerror(errno));
                last_retryable = cert_result_t::NETWORK_SOCKET_FAILURE;
                goto attempt_cleanup;
            }

            if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on fcntl(F_SETFL) for {}:{} - {}", ip, this->m_port, strerror(errno));
                last_retryable = cert_result_t::NETWORK_SOCKET_FAILURE;
                goto attempt_cleanup;
            }

            if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), (family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6))) == -1)
            {
                if (errno != EINPROGRESS)
                {
                    json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_FAILURE)));

                    clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on connect() to {}:{} - {}", ip, this->m_port, strerror(errno));
                    last_retryable = cert_result_t::NETWORK_SOCKET_FAILURE;
                    goto attempt_cleanup;
                }
            }

            //
            // select on the socket to wait for write access
            //
            pfd.fd = sock;
            pfd.events = POLLOUT;

            ret = poll(&pfd, 1, 10000);
            if (ret <= 0)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_TIMEOUT)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): timeout on connect attempt to {}:{} - {}", ip, this->m_port, strerror(errno));
                last_retryable = cert_result_t::NETWORK_SOCKET_TIMEOUT;
                goto attempt_cleanup;
            }
            if ( (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 )
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): poll() reported socket error on {}:{}.", ip, this->m_port);
                last_retryable = cert_result_t::NETWORK_SOCKET_FAILURE;
                goto attempt_cleanup;
            }
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &ret, &socket_error_length) == -1)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on getsockopt(SO_ERROR) for {}:{} - {}", ip, this->m_port, strerror(errno));
                last_retryable = cert_result_t::NETWORK_SOCKET_FAILURE;
                goto attempt_cleanup;
            }
            if (ret != 0)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): connect() did not complete for {}:{} - {}", ip, this->m_port, strerror(ret));
                last_retryable = cert_result_t::NETWORK_SOCKET_FAILURE;
                goto attempt_cleanup;
            }

            //
            // restore blocking
            //
            if (fcntl(sock, F_SETFL, flags) == -1)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed to restore socket flags for {}:{} - {}", ip, this->m_port, strerror(errno));
                last_retryable = cert_result_t::NETWORK_SOCKET_FAILURE;
                goto attempt_cleanup;
            }

            //
            // set the default send/receive timeouts
            //
            if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on setsockopt(SO_RCVTIMEO) for {}:{} - {}", ip, this->m_port, strerror(errno));
                last_retryable = cert_result_t::NETWORK_SOCKET_FAILURE;
                goto attempt_cleanup;
            }
            if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SOCKET_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on setsockopt(SO_SNDTIMEO) for {}:{} - {}", ip, this->m_port, strerror(errno));
                last_retryable = cert_result_t::NETWORK_SOCKET_FAILURE;
                goto attempt_cleanup;
            }

            //
            // set up the protocol socket
            //
            protocol.sock(sock);

            //
            // this will only execute it on protocols that use it
            //
            if (protocol.starttls() == false)
            {
                cert_result_t rc = protocol.result_code();

                json_array_append_new(error_codes, json_integer(static_cast<int>(rc)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on starttls()");
                last_retryable = rc;
                goto attempt_cleanup;
            }

            //
            // create a new SSL context
            //
            ctx = SSL_CTX_new(TLS_client_method());
            if (ctx == nullptr)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_INTERNAL_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on SSL_ctx_new()");
                goto attempt_cleanup;
            }

            //
            // create a new SSL object
            //
            ssl = SSL_new(ctx);
            if (ssl == nullptr)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_INTERNAL_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on SSL_new()");
                goto attempt_cleanup;
            }

            //
            // attach it to our already connected socket
            //
            SSL_set_fd(ssl, sock);

            //
            // add our hostname to SNI
            //
            if (SSL_set_tlsext_host_name(ssl, ((this->m_sni_hostname.length() > 0) ? this->m_sni_hostname.c_str() : this->m_hostname.c_str())) != 1)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_INTERNAL_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on SSL_set_tlsext_host_name()");
                goto attempt_cleanup;
            }

            //
            // connect - this executes the handshake
            //
            if (SSL_connect(ssl) != 1)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_SSL_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on SSL_connect()");
                last_retryable = cert_result_t::NETWORK_SSL_FAILURE;
                goto attempt_cleanup;
            }

            //
            // now ingest any banners off the socket
            //
            protocol.init(ssl);

            //
            // get the full certificate chain;
            //
            // openssl returns the leaf certificate along with the chain
            //
            chain = SSL_get_peer_cert_chain(ssl);
            if (chain == nullptr)
            {
                json_array_append_new(error_codes, json_integer(static_cast<int>(cert_result_t::NETWORK_INTERNAL_FAILURE)));

                clog::instance().log(LOG_WARN, "ctask_cert::run(): failed on SSL_get_peer_cert_chain()");
                goto attempt_cleanup;
            }
            if (sk_X509_num(chain) > 0)
            {
                //
                // add the leaf
                //
                json_t *cl = json_object();

                json_object_set_new(cl, "cert", json_string(this->pem(sk_X509_value(chain, 0)).c_str()));
                json_object_set_new(cl, "codes", json_null());
                json_object_set_new(stack, "leaf", cl);

                //
                // add an array of intermediate objects
                //
                json_t *ci = json_array();

                for(int x=1; x<sk_X509_num(chain); x++)
                {
                    json_t *inte = json_object();

                    json_object_set_new(inte, "cert", json_string(this->pem(sk_X509_value(chain, x)).c_str()));
                    json_object_set_new(inte, "codes", json_null());
                    json_array_append_new(ci, inte);
                }

                json_object_set_new(stack, "intermediate", ci);

                //
                // add a empty CA
                //
                json_object_set_new(stack, "ca", json_null());
            }

            //
            // gracefully shutdown any connections that we've opened with "STARTTLS"
            //
            protocol.shutdown(ssl);

        attempt_cleanup:
            //
            // close the connection; once we have the certificate, we don't need anything else
            //
            close(sock);

            if (ssl != nullptr)
            {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            if (ctx != nullptr)
            {
                SSL_CTX_free(ctx);
            }

            //
            // if the failure was a transient connection error and we have attempts remaining, retry
            //
            if (ctask_cert::is_fetch_retryable(last_retryable) == true && attempt < FETCH_MAX_ATTEMPTS - 1)
            {
                //
                // abort retries if we're shutting down
                //
                if (cagent::instance().m_running == false)
                {
                    clog::instance().log(LOG_NOTICE, "ctask_cert::run(): shutting down, aborting retry for task {}", this->m_id);
                    break;
                }

                int delay_ms = ctask_cert::retry_delay_ms(attempt + 1);

                clog::instance().log(LOG_WARN, "ctask_cert::run(): connection attempt {}/{} failed, retrying in {}ms...",
                    attempt + 1, FETCH_MAX_ATTEMPTS, delay_ms);

                json_decref(error_codes);
                error_codes = json_array();

                //
                // shutdown-aware sleep - check m_running in small increments
                //
                for (int slept = 0; slept < delay_ms; slept += 100)
                {
                    if (cagent::instance().m_running == false)
                    {
                        break;
                    }

                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }

                //
                // if shutdown was signaled during sleep, abort retries
                //
                if (cagent::instance().m_running == false)
                {
                    clog::instance().log(LOG_NOTICE, "ctask_cert::run(): shutting down during retry sleep, aborting task {}", this->m_id);
                    break;
                }

                continue;
            }

            break;
        }

        //
        // every attempt for this address ultimately failed - emit a single
        // error-level log here, only after all retries are exhausted, so
        // transient blips that later succeed don't raise alarms. error_codes is
        // reset before each retry and stays empty on success, so a non-empty
        // array means the final attempt failed
        //
        if (json_array_size(error_codes) > 0)
        {
            clog::instance().log(LOG_ERROR, "ctask_cert::run(): certificate check failed for {} ({}:{}).",
                this->m_hostname, ip, this->m_port);
        }

        //
        // add the certificate chain & list of error codes (if any)
        //
        json_object_set_new(stack, "codes", error_codes);

        json_array_append_new(stack_list, stack);
    }

finished:

    //
    // build the response object, which includes the task id and the result set
    //
    json_t *response = json_object();

    json_object_set_new(response, "id", json_string(this->m_id.c_str()));
    json_object_set_new(response, "monitor", json_integer(this->m_monitor));
    json_object_set_new(response, "profile", json_integer(this->m_profile));
    json_object_set_new(response, "hostname", json_string(this->m_hostname.c_str()));
    json_object_set_new(response, "sni_hostname", json_string(this->m_sni_hostname.c_str()));
    json_object_set_new(response, "protocol", json_integer(static_cast<int>(this->m_protocol)));
    json_object_set_new(response, "port", json_integer(this->m_port));
    json_object_set_new(response, "event_type", json_integer(this->m_event_type));
    json_object_set_new(response, "data", stack_list);
    json_object_set_new(response, "codes", stack_error_codes);

    //
    // dump out the full JSON object
    //
    char *json = json_dumps(response, JSON_COMPACT);
    json_decref(response);

    if (json == nullptr)
    {
        clog::instance().log(LOG_ERROR, "ctask_cert::run(): failed to generate json string for output.");
    } else
    {
        this->complete(json);
        free(json);
    }

    clog::instance().log(LOG_NOTICE, "completed check for task id={}.", this->m_id);

    return true;
}
//
// convert an X509 object to a string
//
std::string ctask_cert::pem(const X509 *_cert)
{
    std::string out;

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr)
    {
        clog::instance().log(LOG_ERROR, "ctask_cert::pem(): failed on BIO_new()");
        return out;
    }

    PEM_write_bio_X509(bio, _cert);
    BUF_MEM* bptr = nullptr;

    BIO_get_mem_ptr(bio, &bptr);
    out.assign(bptr->data, bptr->length);
    BIO_free(bio);

    return out;
}
bool ctask_cert::valid_protocol() const
{
    return ( (this->m_protocol >= cert_protocol_t::HTTPS) && (this->m_protocol <= cert_protocol_t::SIPS) );
}
bool ctask_cert::valid_address_type() const
{
    return ( (this->m_address_type >= profile_address_type_t::DUAL) && (this->m_address_type <= profile_address_type_t::IPV6) );
}

//
// is the provided hostname an IP address?
//
profile_address_type_t ctask_cert::is_ip(const std::string &_data)
{
    struct in_addr ipv4_addr;
    struct in6_addr ipv6_addr;

    if (inet_pton(AF_INET, _data.c_str(), &ipv4_addr) == 1)
    {
        return profile_address_type_t::IPV4;
    }
    if (inet_pton(AF_INET6, _data.c_str(), &ipv6_addr) == 1)
    {
        return profile_address_type_t::IPV6;
    }

    return profile_address_type_t::NONE;
}

//
// lookup all the ipv4 & ipv6 addresses for the given hostname
//
std::vector<std::string> ctask_cert::lookup(const std::string &_hn, const json_t *_ov, const profile_address_type_t _ad)
{
    std::vector<std::string> out;

    //
    // check if the host they gave us is an IP
    //
    profile_address_type_t type = this->is_ip(_hn);

    //
    // if the profile type doesn't work with the host type they gave us
    //
    if ( (type == profile_address_type_t::IPV4) && ((_ad != profile_address_type_t::IPV4) && (_ad != profile_address_type_t::DUAL)) )
    {
        clog::instance().log(LOG_WARN, "ctask_cert::lookup({}): profile is {} but host type is {}.", _hn, static_cast<int>(_ad), static_cast<int>(type));
        return out;
    }
    if ( (type == profile_address_type_t::IPV6) && ((_ad != profile_address_type_t::IPV6) && (_ad != profile_address_type_t::DUAL)) )
    {
        clog::instance().log(LOG_WARN, "ctask_cert::lookup({}): profile is {} but host type is {}.", _hn, static_cast<int>(_ad), static_cast<int>(type));
        return out;
    }

    //
    // if they gave us an IP, then add it to the list and return right away
    //
    if ( (type == profile_address_type_t::IPV4) || (type == profile_address_type_t::IPV6) )
    {
        out.push_back(_hn);
        return out;
    }

    //
    // if there's a list of override IPs, then use those directly
    //
    if ( (_ov != nullptr) && (json_is_array(_ov) != 0) && (json_array_size(_ov) > 0) )
    {
        size_t index = 0;
        json_t *value = nullptr;

        json_array_foreach(_ov, index, value)
        {
            if (json_is_string(value) == 0)
            {
                clog::instance().log(LOG_WARN, "ctask_cert::lookup(): override value must be a string.");
                continue;
            }

            std::string ov(json_string_value(value));
            profile_address_type_t ov_type = this->is_ip(ov);

            if ( (ov_type == profile_address_type_t::IPV4) && ((_ad != profile_address_type_t::IPV4) && (_ad != profile_address_type_t::DUAL)) )
            {
                clog::instance().log(LOG_WARN, "ctask_cert::lookup(): profile address type {} does not support ipv4 override value {}.", static_cast<int>(_ad), ov);
                continue;
            }
            if ( (ov_type == profile_address_type_t::IPV6) && ((_ad != profile_address_type_t::IPV6) && (_ad != profile_address_type_t::DUAL)) )
            {
                clog::instance().log(LOG_WARN, "ctask_cert::lookup(): profile address type {} does not support ipv6 override value {}.", static_cast<int>(_ad), ov);
                continue;
            }

            out.push_back(ov);
        }

    //
    // otherwise build a list from DNS
    //
    } else
    {
        struct addrinfo hints;
        struct addrinfo *res = nullptr;
        struct addrinfo *p = nullptr;

        std::memset(&hints, 0, sizeof(hints));

        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int err = getaddrinfo(_hn.c_str(), nullptr, &hints, &res);
        if (err != 0)
        {
            clog::instance().log(LOG_WARN, "ctask_cert::lookup({}): failed on getaddrinfo(): {}", _hn, gai_strerror(err));
            return out;
        }

        for(p=res; p!=nullptr; p=p->ai_next)
        {
            char ip[INET6_ADDRSTRLEN];
            std::memset(ip, 0, sizeof(ip));

            void *addr = nullptr;

            if (p->ai_family == AF_INET)
            {
                addr = &(reinterpret_cast<struct sockaddr_in*>(p->ai_addr))->sin_addr;

                if ( (_ad == profile_address_type_t::DUAL) || (_ad == profile_address_type_t::IPV4) )
                {
                    inet_ntop(p->ai_family, addr, ip, sizeof(ip));
                    out.emplace_back(ip);
                }

            } else if (p->ai_family == AF_INET6)
            {
                addr = &(reinterpret_cast<struct sockaddr_in6*>(p->ai_addr))->sin6_addr;

                if ( (_ad == profile_address_type_t::DUAL) || (_ad == profile_address_type_t::IPV6) )
                {
                    inet_ntop(p->ai_family, addr, ip, sizeof(ip));
                    out.emplace_back(ip);
                }

            } else
            {
                continue;
            }
        }

        freeaddrinfo(res);
    }

    return out;
}
