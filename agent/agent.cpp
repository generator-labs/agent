//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#include <signal.h>
#include "version.h"
#include "cagent.h"
#include "cexception.h"
#include "clog.h"

//
// main process
//
int main(void)
{
    //
    // Setup the process signals.
    //
    struct sigaction s_exit   = {};
    struct sigaction s_ignore = {};

    s_ignore.sa_handler = SIG_IGN;
    s_ignore.sa_flags = 0;
    sigemptyset(&s_ignore.sa_mask);

    s_exit.sa_handler = cagent::exit_handler;
    s_exit.sa_flags = 0;
    sigemptyset(&s_exit.sa_mask);

    sigaction(SIGPIPE,  &s_ignore, nullptr);
    sigaction(SIGUSR1,  &s_ignore, nullptr);
    sigaction(SIGUSR2,  &s_ignore, nullptr);
    sigaction(SIGCHLD,  &s_ignore, nullptr);
    sigaction(SIGHUP,   &s_ignore, nullptr);

    sigaction(SIGINT,   &s_exit, nullptr);
    sigaction(SIGTERM,  &s_exit, nullptr);

    try
    {
        cagent::instance().run();

    } catch(cexception &e)
    {
        clog::instance().log(LOG_ERROR, "main(): {}", e.what());
    }

    return 0;
}
