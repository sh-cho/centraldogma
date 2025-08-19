/*
 * Copyright 2025 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.linecorp.centraldogma.server.metadata;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

class IpAccessControlUtilsTest {

    @Test
    void validateCidr() {
        // Valid IPv4 CIDR
        assertThat(IpAccessControlUtils.validateCidr("192.168.1.0/24")).isEqualTo("192.168.1.0/24");
        assertThat(IpAccessControlUtils.validateCidr("10.0.0.0/8")).isEqualTo("10.0.0.0/8");
        assertThat(IpAccessControlUtils.validateCidr("172.16.0.0/16")).isEqualTo("172.16.0.0/16");
        
        // Single IPv4 address
        assertThat(IpAccessControlUtils.validateCidr("192.168.1.1")).isEqualTo("192.168.1.1/32");
        assertThat(IpAccessControlUtils.validateCidr("10.0.0.1")).isEqualTo("10.0.0.1/32");
        
        // Valid IPv6 CIDR
        assertThat(IpAccessControlUtils.validateCidr("2001:db8::/32")).isEqualTo("2001:db8::/32");
        assertThat(IpAccessControlUtils.validateCidr("::1")).isEqualTo("::1/128");
        
        // Whitespace handling
        assertThat(IpAccessControlUtils.validateCidr("  192.168.1.0/24  ")).isEqualTo("192.168.1.0/24");
        
        // Invalid CIDR
        assertThatThrownBy(() -> IpAccessControlUtils.validateCidr(""))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("CIDR cannot be empty");
        
        assertThatThrownBy(() -> IpAccessControlUtils.validateCidr("invalid"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid IP address");
        
        assertThatThrownBy(() -> IpAccessControlUtils.validateCidr("192.168.1.0/33"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid prefix length");
        
        assertThatThrownBy(() -> IpAccessControlUtils.validateCidr("192.168.1.0/-1"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid prefix length");
    }

    @Test
    void matchesCidr() throws UnknownHostException {
        // IPv4 network matching
        assertThat(IpAccessControlUtils.matchesCidr("192.168.1.10", "192.168.1.0/24")).isTrue();
        assertThat(IpAccessControlUtils.matchesCidr("192.168.1.255", "192.168.1.0/24")).isTrue();
        assertThat(IpAccessControlUtils.matchesCidr("192.168.2.1", "192.168.1.0/24")).isFalse();
        
        // Single IP matching
        assertThat(IpAccessControlUtils.matchesCidr("192.168.1.1", "192.168.1.1/32")).isTrue();
        assertThat(IpAccessControlUtils.matchesCidr("192.168.1.2", "192.168.1.1/32")).isFalse();
        
        // Large network
        assertThat(IpAccessControlUtils.matchesCidr("10.1.2.3", "10.0.0.0/8")).isTrue();
        assertThat(IpAccessControlUtils.matchesCidr("11.1.2.3", "10.0.0.0/8")).isFalse();
        
        // IPv6 matching
        assertThat(IpAccessControlUtils.matchesCidr("2001:db8::1", "2001:db8::/32")).isTrue();
        assertThat(IpAccessControlUtils.matchesCidr("2001:db9::1", "2001:db8::/32")).isFalse();
        assertThat(IpAccessControlUtils.matchesCidr("::1", "::1/128")).isTrue();
        assertThat(IpAccessControlUtils.matchesCidr("::2", "::1/128")).isFalse();
        
        // InetAddress overload
        InetAddress addr = InetAddress.getByName("192.168.1.10");
        assertThat(IpAccessControlUtils.matchesCidr(addr, "192.168.1.0/24")).isTrue();
        assertThat(IpAccessControlUtils.matchesCidr(addr, "192.168.2.0/24")).isFalse();
        
        // Invalid IP or CIDR
        assertThat(IpAccessControlUtils.matchesCidr("invalid-ip", "192.168.1.0/24")).isFalse();
        
        assertThatThrownBy(() -> IpAccessControlUtils.matchesCidr("192.168.1.1", "invalid-cidr"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void evaluateIpAccessRules() {
        // No rules - allow by default
        assertThat(IpAccessControlUtils.evaluateIpAccessRules("192.168.1.1", null)).isTrue();
        assertThat(IpAccessControlUtils.evaluateIpAccessRules("192.168.1.1", Collections.emptyList())).isTrue();
        
        // Single ALLOW rule
        List<IpAccessControlRule> allowRule = Arrays.asList(
            new IpAccessControlRule(IpAccessControlRule.Action.ALLOW, "192.168.1.0/24", "Internal network")
        );
        assertThat(IpAccessControlUtils.evaluateIpAccessRules("192.168.1.10", allowRule)).isTrue();
        assertThat(IpAccessControlUtils.evaluateIpAccessRules("192.168.2.10", allowRule)).isTrue(); // No match, default allow
        
        // Single DENY rule
        List<IpAccessControlRule> denyRule = Arrays.asList(
            new IpAccessControlRule(IpAccessControlRule.Action.DENY, "192.168.1.0/24", "Block internal network")
        );
        assertThat(IpAccessControlUtils.evaluateIpAccessRules("192.168.1.10", denyRule)).isFalse();
        assertThat(IpAccessControlUtils.evaluateIpAccessRules("192.168.2.10", denyRule)).isTrue(); // No match, default allow
        
        // Multiple rules - first match wins
        List<IpAccessControlRule> multipleRules = Arrays.asList(
            new IpAccessControlRule(IpAccessControlRule.Action.DENY, "192.168.1.10/32", "Block specific IP"),
            new IpAccessControlRule(IpAccessControlRule.Action.ALLOW, "192.168.1.0/24", "Allow network"),
            new IpAccessControlRule(IpAccessControlRule.Action.DENY, "0.0.0.0/0", "Block everything else")
        );
        assertThat(IpAccessControlUtils.evaluateIpAccessRules("192.168.1.10", multipleRules)).isFalse(); // First rule matches
        assertThat(IpAccessControlUtils.evaluateIpAccessRules("192.168.1.20", multipleRules)).isTrue(); // Second rule matches
        assertThat(IpAccessControlUtils.evaluateIpAccessRules("10.0.0.1", multipleRules)).isFalse(); // Third rule matches
        
        // Order matters
        List<IpAccessControlRule> orderedRules = Arrays.asList(
            new IpAccessControlRule(IpAccessControlRule.Action.ALLOW, "192.168.1.0/24", "Allow network first"),
            new IpAccessControlRule(IpAccessControlRule.Action.DENY, "192.168.1.10/32", "Block specific IP")
        );
        assertThat(IpAccessControlUtils.evaluateIpAccessRules("192.168.1.10", orderedRules)).isTrue(); // First rule wins
        
        // InetAddress overload
        try {
            InetAddress addr = InetAddress.getByName("192.168.1.10");
            assertThat(IpAccessControlUtils.evaluateIpAccessRules(addr, allowRule)).isTrue();
            assertThat(IpAccessControlUtils.evaluateIpAccessRules(addr, denyRule)).isFalse();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void ipAccessControlRuleEqualsAndHashCode() {
        IpAccessControlRule rule1 = new IpAccessControlRule(
            IpAccessControlRule.Action.ALLOW, "192.168.1.0/24", "Test rule");
        IpAccessControlRule rule2 = new IpAccessControlRule(
            IpAccessControlRule.Action.ALLOW, "192.168.1.0/24", "Test rule");
        IpAccessControlRule rule3 = new IpAccessControlRule(
            IpAccessControlRule.Action.DENY, "192.168.1.0/24", "Test rule");
        
        assertThat(rule1).isEqualTo(rule2);
        assertThat(rule1).isNotEqualTo(rule3);
        assertThat(rule1.hashCode()).isEqualTo(rule2.hashCode());
        assertThat(rule1.hashCode()).isNotEqualTo(rule3.hashCode());
    }

    @Test
    void ipAccessControlRuleToString() {
        IpAccessControlRule rule = new IpAccessControlRule(
            IpAccessControlRule.Action.ALLOW, "192.168.1.0/24", "Internal network");
        
        String str = rule.toString();
        assertThat(str).contains("ALLOW");
        assertThat(str).contains("192.168.1.0/24");
        assertThat(str).contains("Internal network");
    }

    @Test
    void ipAccessControlRuleValidatesOnConstruction() {
        // Should validate CIDR during construction
        assertThatThrownBy(() -> new IpAccessControlRule(
            IpAccessControlRule.Action.ALLOW, "invalid-cidr", null))
                .isInstanceOf(IllegalArgumentException.class);
        
        // Null action should fail
        assertThatThrownBy(() -> new IpAccessControlRule(null, "192.168.1.0/24", null))
                .isInstanceOf(NullPointerException.class);
        
        // Null CIDR should fail
        assertThatThrownBy(() -> new IpAccessControlRule(
            IpAccessControlRule.Action.ALLOW, null, null))
                .isInstanceOf(NullPointerException.class);
    }
}