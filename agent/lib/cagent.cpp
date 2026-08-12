//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#include <cstdio>
#include <cstring>
#include <thread>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include "version.h"
#include "cagent.h"
#include "cexception.h"
#include "ctask_manager.h"
#include "clog.h"

volatile std::sig_atomic_t cagent::m_exit_signal = 0;

cagent::cagent() : m_running(false), m_agent_mode(agent_mode_t::PERSISTENT), m_signal(0), m_shutdown_deadline(), m_agent_sid(), m_agent_token(), m_agent_url(), m_agent_instance_id(), m_agent_proxy(), m_healthcheck_file()
{
    curl_global_init(CURL_GLOBAL_ALL);

    this->env();

    this->m_agent_instance_id = this->uuid();
}
cagent::~cagent()
{
    curl_global_cleanup();
}
void cagent::exit_handler(const int _id)
{
    cagent::m_exit_signal = _id;
}
void cagent::env()
{
    //
    // get the values from the environment
    //
    const char *agent_sid   = std::getenv("GENERATOR_AGENT_SID");
    const char *agent_token = std::getenv("GENERATOR_AGENT_TOKEN");
    const char *agent_url   = std::getenv("GENERATOR_AGENT_URL");
    const char *agent_mode  = std::getenv("GENERATOR_AGENT_MODE");
    const char *agent_proxy = std::getenv("GENERATOR_AGENT_PROXY");
    const char *agent_hc    = std::getenv("GENERATOR_AGENT_HEALTHCHECK_FILE");

    if ( (agent_sid == nullptr) || (std::strlen(agent_sid) != 34) )
    {
        throw cexception("cagent::env(): missing or invalid agent_sid; you must set the GENERATOR_AGENT_SID environment variable.");
    }
    if ( (agent_token == nullptr) || (std::strlen(agent_token) != 64) )
    {
        throw cexception("cagent::env(): missing or invalid agent_token; you must set the GENERATOR_AGENT_TOKEN environment variable.");
    }

    //
    // store these locally
    //
    this->m_agent_sid   = agent_sid;
    this->m_agent_token = agent_token;

    //
    // if an endpoint URL was provided; this is only done for testing
    //
    if ( (agent_url != nullptr) && (std::strlen(agent_url) > 0) )
    {
        this->m_agent_url = agent_url;
    } else
    {
        this->m_agent_url = AGENT_ENDPOINT_URL;
    }

    //
    // if this environment variable is set to true, then we're configured to run once and exit; this is useful in cases where
    // customers want to run the agent as a scheduled task rather than a persistent service.
    //
    this->m_agent_mode = ( (agent_mode != nullptr) && (strncasecmp(agent_mode, "SINGLE", 6) == 0) ) ? agent_mode_t::SINGLE : agent_mode_t::PERSISTENT;

    //
    // if the customer provided an optional HTTP proxy URL to use for agent communication; this proxy is
    // only used to communicate with the agent API endpoint, and not used for any local checks.
    //
    this->m_agent_proxy = ( (agent_proxy != nullptr) && (std::strlen(agent_proxy) > 0) ) ? agent_proxy : "";

    //
    // optional heartbeat file for a container health check. left empty by default: the agent listens on
    // no port, so a check needs this file, but writing it requires a writable path - which a customer
    // running a read-only root filesystem may not want to provide. when the variable is unset we write
    // nothing, and the container simply has no health check (ECS still restarts it on process exit).
    //
    this->m_healthcheck_file = ( (agent_hc != nullptr) && (std::strlen(agent_hc) > 0) ) ? agent_hc : "";
}
std::string cagent::local_ip()
{
    //
    // open a UDP socket and connect to an external address; no data is sent,
    // but the kernel selects the correct source address via the routing table.
    //
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        return {};
    }

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        close(sock);
        return {};
    }

    sockaddr_in local{};
    socklen_t len = sizeof(local);
    if (getsockname(sock, reinterpret_cast<sockaddr*>(&local), &len) < 0)
    {
        close(sock);
        return {};
    }

    close(sock);

    char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf)) ? std::string(buf) : std::string{};
}
std::string cagent::uuid()
{
    uuid_t uuid;
    uuid_generate(uuid);

    char out[37];
    std::memset(&out, 0, sizeof(out));

    uuid_unparse(uuid, out);

    return std::string(out);
}
void cagent::process_signal()
{
    int sig = static_cast<int>(cagent::m_exit_signal);
    if (sig > 0)
    {
        cagent::m_exit_signal = 0;
        this->stop(sig);
    }
}
void cagent::stop(const int _signal)
{
    if (_signal > 0)
    {
        this->m_signal.store(_signal);
    }

    this->m_shutdown_deadline.store(std::chrono::steady_clock::now() + std::chrono::seconds(SHUTDOWN_TIMEOUT_SECS));
    this->m_running.store(false);
}
void cagent::run()
{
    clog::instance().log(LOG_NOTICE, "GeneratorLabs Agent Version {}.{} build {} started.", VERSION, RELEASE, BUILD);
    clog::instance().log(LOG_NOTICE, "> using agent instance id: {}", this->m_agent_instance_id);
    clog::instance().log(LOG_NOTICE, "> using agent sid: {}", this->m_agent_sid);
    clog::instance().log(LOG_NOTICE, "> using agent endpoint url: {}", this->m_agent_url);

    if (this->m_agent_mode == agent_mode_t::SINGLE)
    {
        clog::instance().log(LOG_NOTICE, "> running as single event; exiting after task completes.");
    }

    //
    // build the tasks endpoint
    //
    std::string url = this->m_agent_url + "/" + std::string(VERSION) + "/tasks";

    //
    // store auth info onto the request object
    //
    this->auth(this->m_agent_sid, this->m_agent_token);

    //
    // if a proxy URL was provided, set it on the HTTP client
    //
    if (this->m_agent_proxy.empty() == false)
    {
        this->proxy(this->m_agent_proxy);
    }

    //
    // store the extra headers
    //
    this->header("X-Agent-Instance", this->m_agent_instance_id);
    this->header("X-Agent-Mode", (this->m_agent_mode == agent_mode_t::SINGLE) ? "SINGLE" : "PERSISTENT");

    //
    // include the container's outbound IP so the remote end knows which host originated the request
    //
    std::string ip = this->local_ip();
    if (ip.empty() == false)
    {
        this->header("X-Forwarded-For", ip);
        clog::instance().log(LOG_NOTICE, "> using local ip: {}", ip);
    }

    //
    // mark us as running
    //
    this->m_running = true;
    this->m_shutdown_deadline.store(std::chrono::steady_clock::now() + std::chrono::seconds(SHUTDOWN_TIMEOUT_SECS));

    while(this->m_running == true)
    {
        //
        // heartbeat for the container health check. the agent listens on no port and has nothing else
        // an external check can reach, so this file is the only evidence it is still going round the
        // loop rather than wedged in a request. it is rewritten every cycle, so a check has to look at
        // the modification time - the file existing proves only that we started once
        //
        // the path comes from GENERATOR_AGENT_HEALTHCHECK_FILE and is empty by default; when unset we
        // write nothing, so a read-only root filesystem needs no writable mount. point it at a writable
        // path (a mounted scratch volume) to enable the check. AGENT_RUN_INTERVAL is the poll interval,
        // so a check should allow several of those before calling it hung
        //
        if (this->m_healthcheck_file.empty() == false)
        {
            FILE *hb = fopen(this->m_healthcheck_file.c_str(), "w");
            if (hb != nullptr)
            {
                fclose(hb);
            }
        }

        this->process_signal();
        if (this->m_running == false)
        {
            break;
        }

        if (this->request(url) == true)
        {
            if ( (this->m_buffer.length() > 0) && (this->m_running == true) )
            {
                ctask_manager::instance().process(this->m_buffer);

            } else if (this->m_response_code == 200)
            {
                clog::instance().log(LOG_ERROR, "cagent::run(): received 200 response code, but empty response body.");
            }
        }

        //
        // if we're in "single run" mode, then we exit out right away instead of looping.
        //
        if (this->m_agent_mode == agent_mode_t::SINGLE)
        {
            break;
        }

        //
        // sleep in 1-second increments so we wake promptly on signal
        //
        for (int i = 0; i < AGENT_RUN_INTERVAL && this->m_running == true; i++)
        {
            this->process_signal();
            if (this->m_running == false)
            {
                break;
            }

            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

    //
    // log the signal that triggered shutdown
    //
    int sig = this->m_signal.load();
    if (sig > 0)
    {
        clog::instance().log(LOG_NOTICE, "cagent::run(): caught signal {}, shutting down.", sig);
    }

    //
    // wait for all active workers to complete, with a deadline
    //
    size_t workers = ctask_manager::instance().active_workers();

    if (workers > 0)
    {
        clog::instance().log(LOG_NOTICE, "cagent::run(): shutting down, waiting for {} active worker(s)...", workers);

        auto deadline = this->m_shutdown_deadline.load();

        while(ctask_manager::instance().active_workers() > 0)
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                clog::instance().log(LOG_WARN, "cagent::run(): shutdown deadline reached with {} worker(s) still active, forcing exit",
                    ctask_manager::instance().active_workers());
                break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (ctask_manager::instance().active_workers() == 0)
        {
            clog::instance().log(LOG_NOTICE, "cagent::run(): all workers completed");
        }
    }

    clog::instance().log(LOG_NOTICE, "cagent::run(): shutdown complete");
}
