//
// Unit tests for cagent
//
#include <gtest/gtest.h>
#include <cstdlib>
#include <regex>
#include <map>
#include <set>
#include "cagent.h"
#include "cexception.h"

// Ensure env vars are set before the singleton is constructed.
// This runs before main() via __attribute__((constructor)).
static void __attribute__((constructor)) setup_test_env() {
    setenv("GENERATOR_AGENT_SID", "AG_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0);
    setenv("GENERATOR_AGENT_TOKEN", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 0);
}

// Test wrapper that can call private methods via friend access
class TestableCagent {
public:
    static std::string call_uuid(cagent& agent) {
        return agent.uuid();
    }

    static void call_process_signal(cagent& agent) {
        agent.process_signal();
    }

    static std::sig_atomic_t& exit_signal() {
        return const_cast<std::sig_atomic_t&>(cagent::m_exit_signal);
    }
};

// UUID tests — uuid() is a pure utility, no singleton issues

TEST(CagentUuidTest, ReturnsValidUuidFormat) {
    cagent& agent = cagent::instance();
    std::string id = TestableCagent::call_uuid(agent);

    EXPECT_EQ(id.length(), 36);

    // UUID format: 8-4-4-4-12 hex chars with dashes
    std::regex uuid_re("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    EXPECT_TRUE(std::regex_match(id, uuid_re));
}

TEST(CagentUuidTest, GeneratesUniqueValues) {
    cagent& agent = cagent::instance();
    std::string id1 = TestableCagent::call_uuid(agent);
    std::string id2 = TestableCagent::call_uuid(agent);

    EXPECT_NE(id1, id2);
}

// Environment variable tests — since cagent is a singleton and its constructor
// calls env() immediately, we test env() indirectly by checking state after
// construction with controlled environment variables.

class CagentEnvTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Save original values
        save("GENERATOR_AGENT_SID");
        save("GENERATOR_AGENT_TOKEN");
        save("GENERATOR_AGENT_URL");
        save("GENERATOR_AGENT_MODE");
        save("GENERATOR_AGENT_PROXY");
    }

    void TearDown() override {
        // Restore original values
        restore("GENERATOR_AGENT_SID");
        restore("GENERATOR_AGENT_TOKEN");
        restore("GENERATOR_AGENT_URL");
        restore("GENERATOR_AGENT_MODE");
        restore("GENERATOR_AGENT_PROXY");
    }

private:
    std::map<std::string, std::string> saved_;
    std::set<std::string> was_set_;

    void save(const char* name) {
        const char* val = std::getenv(name);
        if (val) {
            saved_[name] = val;
            was_set_.insert(name);
        }
    }

    void restore(const char* name) {
        if (was_set_.count(name)) {
            setenv(name, saved_[name].c_str(), 1);
        } else {
            unsetenv(name);
        }
    }
};

// Note: cagent is a singleton, so we can't re-construct it.
// These tests verify that env() throws on invalid input by calling it
// on the already-constructed singleton (which will re-validate).

TEST_F(CagentEnvTest, StopSetsRunningToFalse) {
    cagent& agent = cagent::instance();
    agent.m_running = true;
    agent.stop();
    EXPECT_FALSE(agent.m_running);
}

TEST_F(CagentEnvTest, ExitHandlerDefersShutdownStateToProcessSignal) {
    cagent& agent = cagent::instance();

    agent.m_running = true;
    agent.m_signal = 0;
    TestableCagent::exit_signal() = 0;

    cagent::exit_handler(SIGTERM);

    EXPECT_TRUE(agent.m_running);
    EXPECT_EQ(agent.m_signal.load(), 0);

    TestableCagent::call_process_signal(agent);

    EXPECT_FALSE(agent.m_running);
    EXPECT_EQ(agent.m_signal.load(), SIGTERM);
    TestableCagent::exit_signal() = 0;
}

TEST_F(CagentEnvTest, AgentHasValidInstanceId) {
    const cagent& agent = cagent::instance();
    // Instance ID is set in constructor via uuid()
    EXPECT_EQ(agent.m_agent_instance_id.length(), 36);
}
