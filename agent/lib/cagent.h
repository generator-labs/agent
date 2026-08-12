//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#ifndef CAGENT_H
#define CAGENT_H

#include <csignal>
#include <atomic>
#include <chrono>
#include <string>

#include "csingleton.h"
#include "chttp.h"
#include "defines.h"

class cagent : public csingleton<cagent>, public chttp
{
    friend class TestableCagent;

    public:
        std::atomic<bool> m_running;
        std::atomic<agent_mode_t> m_agent_mode;
        std::atomic<int> m_signal;

        //
        // graceful shutdown deadline - set when SIGTERM is received
        //
        std::atomic<std::chrono::steady_clock::time_point> m_shutdown_deadline;

        std::string m_agent_sid;
        std::string m_agent_token;
        std::string m_agent_url;
        std::string m_agent_instance_id;
        std::string m_agent_proxy;
        std::string m_healthcheck_file;

    private:
        static volatile std::sig_atomic_t m_exit_signal;

        void env();
        static std::string uuid();
        static std::string local_ip();
        void process_signal();

    public:
        cagent();
        ~cagent();

        void stop(const int _signal = 0);
        void run();

        static void exit_handler(const int _id);
};

#endif // CAGENT_H
