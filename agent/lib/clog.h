//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#ifndef CLOG_H
#define CLOG_H

#include <format>
#include <string>
#include <cstdio>
#include "csingleton.h"

class clog : public csingleton<clog>
{
    public:
        enum class Level : int {

            Error  = 3,
            Warn   = 4,
            Notice = 5,
            Debug  = 7
        };

        template<typename... Args>
        static void log(Level level, const char* _file, int _line, std::string_view _fmt, Args&&... _args)
        {
            std::string formatted = std::vformat(_fmt, std::make_format_args(_args...));
            formatted += "\n";

            if (level == Level::Debug)
            {
                std::string debug = std::format("[{}:{}] {}\n", _file, _line, formatted);
                formatted = debug;
            }

            FILE* out = (level == Level::Error) ? stderr : stdout;
            std::fwrite(formatted.data(), 1, formatted.size(), out);
            std::fflush(out);
        }
};

#define LOG_ERROR  clog::Level::Error,  __FILE__, __LINE__
#define LOG_WARN   clog::Level::Warn,   __FILE__, __LINE__
#define LOG_NOTICE clog::Level::Notice, __FILE__, __LINE__
#define LOG_DEBUG  clog::Level::Debug,  __FILE__, __LINE__

#endif // CLOG_H
