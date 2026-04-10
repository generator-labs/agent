//
// Unit tests for ctask_manager
//
#include <gtest/gtest.h>
#include <jansson.h>
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
    // Valid payload that reaches thread spawn — thread will fail internally
    // (no real endpoint), but process() returns true
    std::string payload = R"([{
        "id": "task-001",
        "type": 5,
        "data": {
            "monitor": 1,
            "event_type": 1,
            "protocol": 1,
            "port": 443,
            "address_type": 1,
            "hostname": "localhost"
        }
    }])";

    EXPECT_TRUE(mgr.process(payload));
}

TEST_F(CTaskManagerProcessTest, MaxActiveWorkersIsThirtyTwo) {
    EXPECT_EQ(TestableTaskManager::max_active_workers(), 32);
}

TEST_F(CTaskManagerProcessTest, InvalidPayloadDoesNotQueueTasks) {
    size_t pending_before = TestableTaskManager::pending_tasks(mgr);

    EXPECT_TRUE(mgr.process("[{\"id\": \"task-001\", \"type\": 5, \"data\": 42}]"));
    EXPECT_EQ(TestableTaskManager::pending_tasks(mgr), pending_before);
}
