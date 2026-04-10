//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#ifndef CSINGLETON_H
#define CSINGLETON_H

template<typename T>
class csingleton {

    public:
        static T& instance()
        {
            static T inst;
            return inst;
        }

    protected:
        csingleton() = default;
};

#endif // CSINGLETON_H
