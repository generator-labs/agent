//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#include "ctask.h"
#include "version.h"
#include "cagent.h"
#include "clog.h"

//
// complete the task by send a complete response back to the endpoint
//
bool ctask::complete(const char *_data)
{
    //
    // if we're shutting down, still try to send the result - the work is done,
    // we just need to report it; the CURL timeout (30s) provides a natural bound
    //
    if (cagent::instance().m_running == false)
    {
        clog::instance().log(LOG_NOTICE, "ctask::complete(): shutdown in progress, attempting final result POST for task {}", this->m_id);
    }

    //
    // build the complete endpoint
    //
    std::stringstream url;
    url << cagent::instance().m_agent_url << "/" << VERSION << "/complete";

    //
    // store auth info onto the request object
    //
    this->auth(cagent::instance().m_agent_sid, cagent::instance().m_agent_token);

    //
    // store the extra headers
    //
    this->header("X-Agent-Instance", cagent::instance().m_agent_instance_id);
    this->header("X-Agent-Mode", (cagent::instance().m_agent_mode == agent_mode_t::SINGLE) ? "SINGLE" : "PERSISTENT");

    //
    // send the POST request
    //
    if (this->request(url.str(), std::string(_data)) == false)
    {
        clog::instance().log(LOG_ERROR, "ctask::complete(): failed to send task complete payload.");
        return false;
    }

    return true;
}
