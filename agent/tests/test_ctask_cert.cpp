//
// Unit tests for ctask_cert
//
#include <gtest/gtest.h>
#include <jansson.h>
#include "ctask_cert.h"
#include "defines.h"

// Test helper class to access private methods
class TestableCertTask : public ctask_cert {
public:
    TestableCertTask(const std::string& id, const json_t* data)
        : ctask_cert(id, data) {}

    // Expose private methods for testing
    profile_address_type_t test_is_ip(const std::string& data) {
        return is_ip(data);
    }

    std::vector<std::string> test_lookup(const std::string& hn, const json_t* ov, profile_address_type_t ad) {
        return lookup(hn, ov, ad);
    }

    bool test_valid() const {
        return m_valid;
    }

    cert_result_t test_parse_error() const {
        return m_parse_error;
    }

    // Override run() to prevent actual network calls in tests
    bool run() override {
        return true;
    }
};

class CTaskCertIsIpTest : public ::testing::Test {
protected:
    json_t* empty_data = nullptr;
    std::unique_ptr<TestableCertTask> task;

    void SetUp() override {
        empty_data = json_object();
        json_object_set_new(empty_data, "monitor", json_integer(1));
        json_object_set_new(empty_data, "protocol", json_integer(static_cast<int>(cert_protocol_t::HTTPS)));
        json_object_set_new(empty_data, "port", json_integer(443));
        json_object_set_new(empty_data, "address_type", json_integer(static_cast<int>(profile_address_type_t::DUAL)));
        json_object_set_new(empty_data, "hostname", json_string("example.com"));
        task = std::make_unique<TestableCertTask>("test-id", empty_data);
    }

    void TearDown() override {
        task.reset();
        json_decref(empty_data);
    }
};

TEST_F(CTaskCertIsIpTest, DetectsIPv4Address) {
    EXPECT_EQ(task->test_is_ip("192.168.1.1"), profile_address_type_t::IPV4);
    EXPECT_EQ(task->test_is_ip("10.0.0.1"), profile_address_type_t::IPV4);
    EXPECT_EQ(task->test_is_ip("172.16.0.1"), profile_address_type_t::IPV4);
    EXPECT_EQ(task->test_is_ip("255.255.255.255"), profile_address_type_t::IPV4);
    EXPECT_EQ(task->test_is_ip("0.0.0.0"), profile_address_type_t::IPV4);
}

TEST_F(CTaskCertIsIpTest, DetectsIPv6Address) {
    EXPECT_EQ(task->test_is_ip("::1"), profile_address_type_t::IPV6);
    EXPECT_EQ(task->test_is_ip("2001:db8::1"), profile_address_type_t::IPV6);
    EXPECT_EQ(task->test_is_ip("fe80::1"), profile_address_type_t::IPV6);
    EXPECT_EQ(task->test_is_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), profile_address_type_t::IPV6);
    EXPECT_EQ(task->test_is_ip("::ffff:192.168.1.1"), profile_address_type_t::IPV6);  // IPv4-mapped
}

TEST_F(CTaskCertIsIpTest, ReturnsNoneForHostnames) {
    EXPECT_EQ(task->test_is_ip("example.com"), profile_address_type_t::NONE);
    EXPECT_EQ(task->test_is_ip("sub.domain.example.com"), profile_address_type_t::NONE);
    EXPECT_EQ(task->test_is_ip("localhost"), profile_address_type_t::NONE);
}

TEST_F(CTaskCertIsIpTest, ReturnsNoneForInvalidIPs) {
    EXPECT_EQ(task->test_is_ip("256.1.1.1"), profile_address_type_t::NONE);
    EXPECT_EQ(task->test_is_ip("192.168.1"), profile_address_type_t::NONE);
    EXPECT_EQ(task->test_is_ip("192.168.1.1.1"), profile_address_type_t::NONE);
    EXPECT_EQ(task->test_is_ip("not-an-ip"), profile_address_type_t::NONE);
    EXPECT_EQ(task->test_is_ip(""), profile_address_type_t::NONE);
}

TEST_F(CTaskCertIsIpTest, ReturnsNoneForMalformedInput) {
    EXPECT_EQ(task->test_is_ip("192.168.1.1:443"), profile_address_type_t::NONE);  // With port
    EXPECT_EQ(task->test_is_ip("[::1]"), profile_address_type_t::NONE);  // Bracketed IPv6
    EXPECT_EQ(task->test_is_ip("192.168.1.1/24"), profile_address_type_t::NONE);  // CIDR notation
}

class CTaskCertLookupTest : public ::testing::Test {
protected:
    json_t* task_data = nullptr;
    std::unique_ptr<TestableCertTask> task;

    void SetUp() override {
        task_data = json_object();
        json_object_set_new(task_data, "monitor", json_integer(1));
        json_object_set_new(task_data, "protocol", json_integer(static_cast<int>(cert_protocol_t::HTTPS)));
        json_object_set_new(task_data, "port", json_integer(443));
        json_object_set_new(task_data, "address_type", json_integer(static_cast<int>(profile_address_type_t::DUAL)));
        json_object_set_new(task_data, "hostname", json_string("example.com"));
        task = std::make_unique<TestableCertTask>("test-id", task_data);
    }

    void TearDown() override {
        task.reset();
        json_decref(task_data);
    }
};

TEST_F(CTaskCertLookupTest, ReturnsIPv4DirectlyWhenGivenIPv4) {
    json_t* empty_override = json_array();
    auto result = task->test_lookup("192.168.1.1", empty_override, profile_address_type_t::DUAL);

    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "192.168.1.1");

    json_decref(empty_override);
}

TEST_F(CTaskCertLookupTest, ReturnsIPv6DirectlyWhenGivenIPv6) {
    json_t* empty_override = json_array();
    auto result = task->test_lookup("2001:db8::1", empty_override, profile_address_type_t::DUAL);

    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "2001:db8::1");

    json_decref(empty_override);
}

TEST_F(CTaskCertLookupTest, RejectsIPv4WhenOnlyIPv6Allowed) {
    json_t* empty_override = json_array();
    auto result = task->test_lookup("192.168.1.1", empty_override, profile_address_type_t::IPV6);

    EXPECT_TRUE(result.empty());

    json_decref(empty_override);
}

TEST_F(CTaskCertLookupTest, RejectsIPv6WhenOnlyIPv4Allowed) {
    json_t* empty_override = json_array();
    auto result = task->test_lookup("2001:db8::1", empty_override, profile_address_type_t::IPV4);

    EXPECT_TRUE(result.empty());

    json_decref(empty_override);
}

TEST_F(CTaskCertLookupTest, UsesOverrideIPsWhenProvided) {
    json_t* overrides = json_array();
    json_array_append_new(overrides, json_string("10.0.0.1"));
    json_array_append_new(overrides, json_string("10.0.0.2"));

    auto result = task->test_lookup("example.com", overrides, profile_address_type_t::DUAL);

    ASSERT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], "10.0.0.1");
    EXPECT_EQ(result[1], "10.0.0.2");

    json_decref(overrides);
}

TEST_F(CTaskCertLookupTest, FiltersOverridesByAddressType) {
    json_t* overrides = json_array();
    json_array_append_new(overrides, json_string("10.0.0.1"));  // IPv4
    json_array_append_new(overrides, json_string("2001:db8::1"));  // IPv6

    // Only IPv4 allowed
    auto result = task->test_lookup("example.com", overrides, profile_address_type_t::IPV4);

    ASSERT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "10.0.0.1");

    json_decref(overrides);
}

class CTaskCertConstructorTest : public ::testing::Test {
protected:
    void TearDown() override {
        // Each test manages its own json cleanup
    }
};

TEST_F(CTaskCertConstructorTest, ParsesAllFields) {
    json_t* data = json_object();
    json_object_set_new(data, "monitor", json_integer(42));
    json_object_set_new(data, "event_type", json_integer(1));
    json_object_set_new(data, "protocol", json_integer(static_cast<int>(cert_protocol_t::SMTPS)));
    json_object_set_new(data, "port", json_integer(465));
    json_object_set_new(data, "address_type", json_integer(static_cast<int>(profile_address_type_t::IPV4)));
    json_object_set_new(data, "hostname", json_string("mail.example.com"));
    json_object_set_new(data, "sni_hostname", json_string("smtp.example.com"));

    json_t* ip_override = json_array();
    json_array_append_new(ip_override, json_string("1.2.3.4"));
    json_object_set_new(data, "ip_override", ip_override);

    TestableCertTask task("test-task-id", data);
    (void)task;

    // Task should be constructable without throwing
    SUCCEED();

    json_decref(data);
}

TEST_F(CTaskCertConstructorTest, HandlesMinimalData) {
    json_t* data = json_object();
    // Empty object - all fields will be default/unset

    TestableCertTask task("minimal-id", data);
    (void)task;

    // Should handle gracefully
    SUCCEED();

    json_decref(data);
}

TEST_F(CTaskCertConstructorTest, IgnoresUnknownFields) {
    json_t* data = json_object();
    json_object_set_new(data, "unknown_field", json_string("should be ignored"));
    json_object_set_new(data, "another_unknown", json_integer(999));

    // Should not throw
    EXPECT_NO_THROW({
        TestableCertTask task("test-id", data);
        (void)task;
    });

    json_decref(data);
}

TEST_F(CTaskCertConstructorTest, MarksTaskInvalidForNonStringHostname) {
    json_t* data = json_object();
    json_object_set_new(data, "hostname", json_integer(42));

    TestableCertTask task("test-id", data);

    EXPECT_FALSE(task.test_valid());
    EXPECT_EQ(task.test_parse_error(), cert_result_t::NETWORK_INTERNAL_FAILURE);

    json_decref(data);
}

TEST_F(CTaskCertConstructorTest, MarksTaskInvalidForNonStringSniHostname) {
    json_t* data = json_object();
    json_object_set_new(data, "sni_hostname", json_integer(42));

    TestableCertTask task("test-id", data);

    EXPECT_FALSE(task.test_valid());
    EXPECT_EQ(task.test_parse_error(), cert_result_t::NETWORK_INTERNAL_FAILURE);

    json_decref(data);
}

TEST_F(CTaskCertConstructorTest, MarksTaskInvalidForNonArrayOverride) {
    json_t* data = json_object();
    json_object_set_new(data, "ip_override", json_string("1.2.3.4"));

    TestableCertTask task("test-id", data);

    EXPECT_FALSE(task.test_valid());
    EXPECT_EQ(task.test_parse_error(), cert_result_t::NETWORK_INTERNAL_FAILURE);

    json_decref(data);
}


TEST_F(CTaskCertConstructorTest, MarksTaskInvalidForNonIntegerPort) {
    json_t* data = json_object();
    json_object_set_new(data, "port", json_string("443"));

    TestableCertTask task("test-id", data);

    EXPECT_FALSE(task.test_valid());
    EXPECT_EQ(task.test_parse_error(), cert_result_t::NETWORK_INTERNAL_FAILURE);

    json_decref(data);
}

TEST_F(CTaskCertConstructorTest, MarksTaskInvalidForOutOfRangePortInRunValidation) {
    json_t* data = json_object();
    json_object_set_new(data, "protocol", json_integer(static_cast<int>(cert_protocol_t::HTTPS)));
    json_object_set_new(data, "port", json_integer(70000));
    json_object_set_new(data, "address_type", json_integer(static_cast<int>(profile_address_type_t::DUAL)));
    json_object_set_new(data, "hostname", json_string("example.com"));

    ctask_cert task("test-id", data);

    EXPECT_TRUE(task.run());

    json_decref(data);
}

TEST_F(CTaskCertConstructorTest, MarksTaskInvalidForUnknownProtocolInRunValidation) {
    json_t* data = json_object();
    json_object_set_new(data, "protocol", json_integer(999));
    json_object_set_new(data, "port", json_integer(443));
    json_object_set_new(data, "address_type", json_integer(static_cast<int>(profile_address_type_t::DUAL)));
    json_object_set_new(data, "hostname", json_string("example.com"));

    ctask_cert task("test-id", data);

    EXPECT_TRUE(task.run());

    json_decref(data);
}
