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

import static java.util.Objects.requireNonNull;

import javax.annotation.Nullable;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;

/**
 * Represents an IP access control rule for tokens.
 */
public final class IpAccessControlRule {

    public enum Action {
        ALLOW, DENY
    }

    private final Action action;
    private final String cidr;
    @Nullable
    private final String description;

    /**
     * Creates a new IP access control rule.
     *
     * @param action the action to take when this rule matches
     * @param cidr the CIDR notation for IP range (e.g., "192.168.1.0/24", "10.0.0.1/32")
     * @param description optional description for this rule
     */
    @JsonCreator
    public IpAccessControlRule(@JsonProperty("action") Action action,
                               @JsonProperty("cidr") String cidr,
                               @JsonProperty("description") @Nullable String description) {
        this.action = requireNonNull(action, "action");
        this.cidr = IpAccessControlUtils.validateCidr(cidr);
        this.description = description;
    }

    /**
     * Returns the action to take when this rule matches.
     */
    @JsonProperty
    public Action action() {
        return action;
    }

    /**
     * Returns the CIDR notation for the IP range.
     */
    @JsonProperty
    public String cidr() {
        return cidr;
    }

    /**
     * Returns the optional description for this rule.
     */
    @Nullable
    @JsonProperty
    public String description() {
        return description;
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                          .add("action", action)
                          .add("cidr", cidr)
                          .add("description", description)
                          .toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof IpAccessControlRule)) {
            return false;
        }
        final IpAccessControlRule that = (IpAccessControlRule) obj;
        return action == that.action &&
               cidr.equals(that.cidr) &&
               java.util.Objects.equals(description, that.description);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(action, cidr, description);
    }
}