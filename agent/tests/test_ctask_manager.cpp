//
// Unit tests for ctask_manager
//
#include <gtest/gtest.h>
#include <jansson.h>
#include <chrono>
#include <thread>
#include "ctask_manager.h"

class TestableTaskManager {
public:
    static size_t max_active_workers() {
        return ctask_manager::MAX_ACTIVE_WORKERS;
    }

    static size_t pending_tasks(ctask_manager& mgr) {
        std::lock_guard<std::mutex> guard(mgr.m_lock);
        return mgr.m_pending_tasks.size();
    }
};

class CTaskManagerProcessTest : public ::testing::Test {
protected:
    ctask_manager& mgr = ctask_manager::instance();
};

TEST_F(CTaskManagerProcessTest, EmptyPayloadReturnsFalse) {
    EXPECT_FALSE(mgr.process(""));
}

TEST_F(CTaskManagerProcessTest, InvalidJsonReturnsFalse) {
    EXPECT_FALSE(mgr.process("not json at all"));
}

TEST_F(CTaskManagerProcessTest, NonArrayJsonReturnsFalse) {
    EXPECT_FALSE(mgr.process("{\"key\": \"value\"}"));
}

TEST_F(CTaskManagerProcessTest, ArrayWithNonObjectElementReturnsTrue) {
    EXPECT_TRUE(mgr.process("[42, \"string\", null]"));
}

TEST_F(CTaskManagerProcessTest, ArrayWithMissingTaskIdReturnsTrue) {
    // Object without "id" — skips it, but returns true
    EXPECT_TRUE(mgr.process("[{\"type\": 5}]"));
}

TEST_F(CTaskManagerProcessTest, ArrayWithMissingTaskTypeReturnsTrue) {
    // Object without "type" — skips it, but returns true
    EXPECT_TRUE(mgr.process("[{\"id\": \"abc123\"}]"));
}

TEST_F(CTaskManagerProcessTest, ValidCertCheckPayloadReturnsTrue) {
    // Valid payload structure for a cert check — address_type intentionally omitted
    // so the worker fails at valid_address_type() before any DNS or socket I/O.
    // Including address_type caused the worker to block in poll() on localhost:443,
    // which prevented the jthread from joining on binary exit, stalling the test.
    std::string payload = R"([{
        "id": "task-001",
        "type": 5,
        "data": {
            "monitor": 1,
            "event_type": 1,
            "protocol": 1,
            "port": 443,
            "hostname": "localhost"
        }
    }])";

    EXPECT_TRUE(mgr.process(payload));

    //
    // wait for the worker to terminate so the singleton is clean for subsequent
    // tests and the binary can exit without blocking on jthread::join()
    //
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
    while (mgr.active_workers() > 0 && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

TEST_F(CTaskManagerProcessTest, MaxActiveWorkersIsThirtyTwo) {
    EXPECT_EQ(TestableTaskManager::max_active_workers(), 32);
}

TEST_F(CTaskManagerProcessTest, InvalidPayloadDoesNotQueueTasks) {
    size_t pending_before = TestableTaskManager::pending_tasks(mgr);

    EXPECT_TRUE(mgr.process("[{\"id\": \"task-001\", \"type\": 5, \"data\": 42}]"));
    EXPECT_EQ(TestableTaskManager::pending_tasks(mgr), pending_before);
}
