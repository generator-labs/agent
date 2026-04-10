//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#ifndef CTASK_H
#define CTASK_H

#include <jansson.h>
#include "chttp.h"

class ctask : public chttp
{
    protected:
        std::string m_id;

    public:
        virtual bool run() = 0;

    protected:
        bool complete(const char *_data);
};

#endif // CTASK_H
