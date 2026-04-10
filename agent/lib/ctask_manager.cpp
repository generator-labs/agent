//
// This file is part of the Generator Labs Agent
//
// For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
//
#include <thread>
#include <jansson.h>

#include "ctask_manager.h"
#include "ctask_cert.h"
#include "clog.h"
#include "cexception.h"

ctask_manager::ctask_manager() : m_active_workers(0)
{
}
void ctask_manager::worker(const std::string &_id, const int _type, json_t *_data, std::shared_ptr<std::atomic<bool>> _done)
{
    try
    {
        switch(_type)
        {
            //
            // certificate check
            //
            case static_cast<int>(task_type_t::CERT_CHECK):
            {
                ctask_cert task(_id, _data);
                task.run();
            }
            break;
            default:
            {
                clog::instance().log(LOG_ERROR, "ctask_manager::run(): invalid task type {}.", _type);
            }
        }

    } catch(cexception &e)
    {
        clog::instance().log(LOG_ERROR, "ctask_manager::run(): {}", e.what());
    } catch(std::exception &e)
    {
        clog::instance().log(LOG_ERROR, "ctask_manager::run(): unexpected exception: {}", e.what());
    } catch(...)
    {
        clog::instance().log(LOG_ERROR, "ctask_manager::run(): unknown exception");
    }

    json_decref(_data);

    ctask_manager::instance().m_active_workers--;
    _done->store(true);
    ctask_manager::instance().dispatch_pending();

    return;
}
void ctask_manager::reap_workers()
{
    for (auto it = this->m_workers.begin(); it != this->m_workers.end(); )
    {
        if ( (*it)->done->load() == true )
        {
            if ((*it)->thread.get_id() == std::this_thread::get_id())
            {
                (*it)->thread.detach();
            }

            it = this->m_workers.erase(it);
        } else
        {
            ++it;
        }
    }
}
void ctask_manager::dispatch_pending()
{
    std::lock_guard<std::mutex> guard(this->m_lock);

    this->reap_workers();

    while ( (this->m_active_workers.load() < MAX_ACTIVE_WORKERS) && (this->m_pending_tasks.empty() == false) )
    {
        pending_task_t task = std::move(this->m_pending_tasks.front());
        this->m_pending_tasks.pop_front();

        try
        {
            std::unique_ptr<worker_state_t> worker_state(new worker_state_t{
                std::make_shared<std::atomic<bool>>(false),
                std::jthread()
            });

            this->m_active_workers++;
            worker_state->thread = std::jthread(ctask_manager::worker, task.id, task.type, task.data, worker_state->done);
            this->m_workers.push_back(std::move(worker_state));

        } catch(...)
        {
            this->m_active_workers--;
            json_decref(task.data);
            clog::instance().log(LOG_ERROR, "ctask_manager::process(): failed to spawn worker thread for task {}.", task.id);
        }
    }
}
bool ctask_manager::process(const std::string &_data)
{
    if (_data.length() == 0)
    {
        clog::instance().log(LOG_ERROR, "ctask_manager::process(): empty payload provided.");
        return false;
    }

    //
    // the task data should be an array of task objects; we need to parse the array, and loop through each
    // object and process the task
    //
    json_error_t error;
    json_t *root = json_loads(_data.c_str(), 0, &error);
    if (root == nullptr)
    {
        clog::instance().log(LOG_ERROR, "ctask_manager::process(): failed to load payload '{}' (should be json object)", _data);
        return false;
    }
    if (json_is_array(root) == 0)
    {
        json_decref(root);

        clog::instance().log(LOG_ERROR, "ctask_manager::process(): invalid payload; should be an array of objects.");
        return false;
    }

    //
    // loop through the array
    //
    size_t index = 0;
    json_t *value = nullptr;

    json_array_foreach(root, index, value)
    {
        //
        // each value should be an object
        //
        if (json_is_object(value) == 0)
        {
            clog::instance().log(LOG_ERROR, "ctask_manager::process(): invalid payload; should be an array of objects.");
            continue;
        }

        //
        // get the id value (the sid of task)
        //
        const char *id_str = json_string_value(json_object_get(value, "id"));
        std::string id = (id_str != nullptr) ? id_str : "";
        if (id.length() == 0)
        {
            clog::instance().log(LOG_ERROR, "ctask_manager::process(): invalid payload; missing task id.");
            continue;
        }

        //
        // get the type value (the type of task)
        //
        int type = json_integer_value(json_object_get(value, "type"));
        if (type == 0)
        {
            clog::instance().log(LOG_ERROR, "ctask_manager::process(): invalid payload; missing task type.");
            continue;
        }

        //
        // based on the task type
        //
        switch(type)
        {
            //
            // all supported tasks types
            //
            case static_cast<int>(task_type_t::CERT_CHECK):
            {
                json_t *data = json_object_get(value, "data");
                if (json_is_object(data) == 0)
                {
                    clog::instance().log(LOG_ERROR, "ctask_manager::process(): failed to extract data payment for certificate check.");
                    continue;
                }

                //
                // increment the reference so I can pass it into the thread without losing it
                //
                json_incref(data);

                //
                // queue the task and dispatch workers up to the active cap
                //
                {
                    std::lock_guard<std::mutex> guard(this->m_lock);
                    this->m_pending_tasks.push_back({ id, type, data });
                }

                this->dispatch_pending();
            }
            break;
            default:
            {
                clog::instance().log(LOG_ERROR, "ctask_manager::process(): unknown over invalid task type {}.", type);
            }
        }
    }

    json_decref(root);

    return true;
}
