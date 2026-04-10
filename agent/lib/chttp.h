//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#ifndef CHTTP_H
#define CHTTP_H

#include <sstream>
#include <string>
#include <unordered_map>
#include <curl/curl.h>

#include "version.h"
#include "clog.h"

class chttp
{
    friend class TestableHttp;  // For unit testing

    protected:

        //
        // used for authentication
        //
        std::string m_user;
        std::string m_pass;

        //
        // an optional proxy URL
        //
        std::string m_proxy_url;

        //
        // request headers
        //
        std::unordered_multimap<std::string, std::string> m_request_headers;

        //
        // response buffer & return code
        //
        std::string m_buffer;
        std::unordered_multimap<std::string, std::string> m_response_headers;
        long m_response_code;

    private:

        //
        // header call-back for the curl request
        //
        static size_t header_callback(char *_contents, size_t _size, size_t _nmemb, void *_data)
        {
            auto buffer = static_cast<std::unordered_multimap<std::string, std::string>*>(_data);

            size_t total = _size * _nmemb;
            std::string line(_contents, total);

            //
            // igore the response line and any line with a colon in it
            //
            if ( (line.starts_with("HTTP/") == true) || (line.find(':') == std::string::npos) )
            {
                return total;
            }

            //
            // parse the key/value
            //
            std::string key = line.substr(0, line.find(':'));
            size_t sep = line.find(':');
            std::string val = line.substr(sep + 1);
            if (!val.empty() && val.front() == ' ') val.erase(0, 1);

            if ( (val.empty() == false) && (val.back() == '\n') ) val.pop_back();
            if ( (val.empty() == false) && (val.back() == '\r') ) val.pop_back();

            //
            // lowercase the key - just in case
            //
            std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c){ return std::tolower(c); });

            buffer->emplace(std::move(key), std::move(val));

            return total;
        }

        //
        // write call-back for the curl request
        //
        static size_t write_callback(char *_contents, size_t _size, size_t _nmemb, void *_data)
        {
            auto* buffer = static_cast<std::string*>(_data);

            buffer->append(_contents, _size * _nmemb);

            return _size * _nmemb;
        }

    protected:

        chttp() : m_user(), m_pass(), m_proxy_url(), m_request_headers(), m_buffer(), m_response_code(0)
        {
        }
        void auth(const std::string &_user, const std::string &_pass)
        {
            this->m_user = _user;
            this->m_pass = _pass;
        }
        void header(const std::string &_key, const std::string &_value)
        {
            this->m_request_headers.emplace(_key, _value);
        }
        void proxy(const std::string &_proxy)
        {
            this->m_proxy_url = _proxy;
        }
        bool request(const std::string &_url, const std::string &_post = {})
        {
            this->m_buffer.clear();
            this->m_response_headers.clear();

            //
            // build the useragent header
            //
            std::string agent = "GeneratorAgent/" + std::string(VERSION) + "." + std::string(RELEASE);

            //
            // build the auth header
            //
            std::string userpwd = this->m_user + ":" + this->m_pass;

            //
            // add the content-type header if not already set
            //
            if (this->m_request_headers.find("Content-Type") == this->m_request_headers.end())
            {
                this->header("Content-Type", "application/json");
            }

            //
            // set up curl
            //
            CURL *curl = curl_easy_init();
            if (curl == nullptr)
            {
                clog::instance().log(LOG_ERROR, "chttp::request(): failed on curl_easy_init().");
                return false;
            }

            //
            // loop through all the request headers and add them
            //
            struct curl_slist *headers = nullptr;

            for(const auto& [key, value]: this->m_request_headers)
            {
                headers = curl_slist_append(headers, std::format("{}: {}", key, value).c_str());
                if (headers == nullptr)
                {
                    curl_easy_cleanup(curl);

                    clog::instance().log(LOG_ERROR, "chttp::request(): failed on curl_slist_append().");
                    return false;
                }
            }

            curl_easy_setopt(curl, CURLOPT_URL, _url.c_str());
            curl_easy_setopt(curl, CURLOPT_USERAGENT, agent.c_str());
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &this->m_buffer);
            curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_callback);
            curl_easy_setopt(curl, CURLOPT_HEADERDATA, &this->m_response_headers);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_USERPWD, userpwd.c_str());
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

            //
            // if there's POST data, then send it as a POST request instead of GET
            //
            if (_post.length() > 0)
            {
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, _post.data());
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, _post.size());
            }

            //
            // if the customer provided an optional HTTP proxy to route through
            //
            if (this->m_proxy_url.length() > 0)
            {
                curl_easy_setopt(curl, CURLOPT_PROXY, this->m_proxy_url.c_str());
            }

            //
            // execute the request
            //
            CURLcode res = curl_easy_perform(curl);
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &this->m_response_code);

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);

            switch(this->m_response_code)
            {
                case 500:   // server failure of some kind
                case 400:   // bad endpoint version; this application needs to be updated
                case 401:   // authentication failure
                {
                    auto error = this->m_response_headers.find("x-failure");

                    if (error != this->m_response_headers.end())
                    {
                        clog::instance().log(LOG_ERROR, "chttp::request(): {}", error->second);
                    } else
                    {
                        clog::instance().log(LOG_ERROR, "chttp::request(): endpoint returned {} error, but no failure header.", this->m_response_code);
                    }

                    return false;
                }
                break; // cppcheck-suppress duplicateBreak

                //
                // successful connection
                //
                case 202:
                case 200:
                {
                    return true;
                }
                break; // cppcheck-suppress duplicateBreak
                default:
                {
                    clog::instance().log(LOG_ERROR, "chttp::request(): unknown or unhandled response code={} error={}.", this->m_response_code, curl_easy_strerror(res));
                }
            }

            return false;
        }
};

#endif // CHTTP_H
