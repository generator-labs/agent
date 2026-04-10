//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#ifndef CEXCEPTION_H
#define CEXCEPTION_H

#include <exception>
#include <string>
#include <format>

class cexception : public std::exception
{
    private:
        std::string m_message;

    public:
        template<typename... Args>
        explicit cexception(std::string_view fmt, Args&&... args) : m_message(std::vformat(fmt, std::make_format_args(args...)))
        {
        }
        [[nodiscard]] const char* what() const noexcept override
        {
            return m_message.c_str();
        }
};

#endif // CEXCEPTION_H
