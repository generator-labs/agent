//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#ifndef CTASK_MANAGER_H
#define CTASK_MANAGER_H

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <jansson.h>

#include "csingleton.h"
#include "defines.h"

class ctask_manager : public csingleton<ctask_manager>
{
    friend class TestableTaskManager;

    private:
        typedef struct {
            std::string id;
            int type;
            json_t *data;
        } pending_task_t;

        typedef struct {
            std::shared_ptr<std::atomic<bool>> done;
            std::jthread thread;
        } worker_state_t;

        static constexpr size_t MAX_ACTIVE_WORKERS = 32;

        std::atomic<size_t> m_active_workers;
        std::mutex m_lock;
        std::deque<pending_task_t> m_pending_tasks;
        std::vector<std::unique_ptr<worker_state_t>> m_workers;

        static void worker(const std::string &_id, const int _type, json_t *_data, std::shared_ptr<std::atomic<bool>> _done);

        void reap_workers();
        void dispatch_pending();

    public:
        ctask_manager();

        bool process(const std::string &_data);

        size_t active_workers() const { return this->m_active_workers.load(); }
};

#endif // CTASK_MANAGER_H
