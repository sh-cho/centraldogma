/*
 * Copyright 2019 LINE Corporation
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

import static com.google.common.base.MoreObjects.firstNonNull;
import static java.util.Objects.requireNonNull;

import java.util.Collections;
import java.util.List;

import javax.annotation.Nullable;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableList;

import com.linecorp.centraldogma.common.ProjectRole;
import com.linecorp.centraldogma.internal.Util;

/**
 * Specifies details of an application token.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(Include.NON_NULL)
public final class Token implements Identifiable {

    /**
     * An application identifier.
     */
    private final String appId;

    /**
     * A secret which is used to access an HTTP API.
     */
    @Nullable
    private final String secret;

    /**
     * Specifies whether this token is for system administrators.
     */
    private final boolean isSystemAdmin;

    private final boolean allowGuestAccess;

    /**
     * Specifies when this token is created by whom.
     */
    private final UserAndTimestamp creation;

    /**
     * Specifies when this repository is removed by whom.
     */
    @Nullable
    private final UserAndTimestamp deactivation;

    @Nullable
    private final UserAndTimestamp deletion;

    /**
     * IP access control rules for this token.
     */
    private final List<IpAccessControlRule> ipAccessControlRules;

    Token(String appId, String secret, boolean isSystemAdmin, boolean allowGuestAccess,
          UserAndTimestamp creation) {
        this(appId, secret, null, isSystemAdmin, allowGuestAccess, creation, null, null, null);
    }

    /**
     * Creates a new instance.
     */
    @JsonCreator
    public Token(@JsonProperty("appId") String appId,
                 @JsonProperty("secret") String secret,
                 // TODO(minwoox): Remove admin field after all tokens are migrated.
                 @JsonProperty("admin") @Nullable Boolean isAdmin,
                 @JsonProperty("systemAdmin") @Nullable Boolean isSystemAdmin,
                 @JsonProperty("allowGuestAccess") @Nullable Boolean allowGuestAccess,
                 @JsonProperty("creation") UserAndTimestamp creation,
                 @JsonProperty("deactivation") @Nullable UserAndTimestamp deactivation,
                 @JsonProperty("deletion") @Nullable UserAndTimestamp deletion,
                 @JsonProperty("ipAccessControlRules") @Nullable List<IpAccessControlRule> ipAccessControlRules) {
        assert isAdmin != null || isSystemAdmin != null;
        this.appId = Util.validateFileName(appId, "appId");
        this.secret = Util.validateFileName(secret, "secret");
        this.isSystemAdmin = isSystemAdmin != null ? isSystemAdmin : isAdmin;
        // Allow guest access by default for backward compatibility.
        this.allowGuestAccess = firstNonNull(allowGuestAccess, true);
        this.creation = requireNonNull(creation, "creation");
        this.deactivation = deactivation;
        this.deletion = deletion;
        this.ipAccessControlRules = ipAccessControlRules == null ? 
                Collections.emptyList() : ImmutableList.copyOf(ipAccessControlRules);
    }

    private Token(String appId, boolean isSystemAdmin, boolean allowGuestAccess, UserAndTimestamp creation,
                  @Nullable UserAndTimestamp deactivation, @Nullable UserAndTimestamp deletion) {
        this(appId, isSystemAdmin, allowGuestAccess, creation, deactivation, deletion, null);
    }

    private Token(String appId, boolean isSystemAdmin, boolean allowGuestAccess, UserAndTimestamp creation,
                  @Nullable UserAndTimestamp deactivation, @Nullable UserAndTimestamp deletion,
                  @Nullable List<IpAccessControlRule> ipAccessControlRules) {
        this.appId = Util.validateFileName(appId, "appId");
        this.isSystemAdmin = isSystemAdmin;
        this.allowGuestAccess = allowGuestAccess;
        this.creation = requireNonNull(creation, "creation");
        this.deactivation = deactivation;
        this.deletion = deletion;
        this.ipAccessControlRules = ipAccessControlRules == null ? 
                Collections.emptyList() : ImmutableList.copyOf(ipAccessControlRules);
        secret = null;
    }

    @Override
    public String id() {
        return appId;
    }

    /**
     * Returns the ID of the application.
     */
    @JsonProperty
    public String appId() {
        return appId;
    }

    /**
     * Returns the secret.
     */
    @Nullable
    @JsonProperty
    public String secret() {
        return secret;
    }

    /**
     * Returns whether this token has system administrative privileges.
     */
    @JsonProperty
    public boolean isSystemAdmin() {
        return isSystemAdmin;
    }

    /**
     * Returns whether this token allows {@link ProjectRole#GUEST} access.
     */
    @JsonProperty
    public boolean allowGuestAccess() {
        return allowGuestAccess;
    }

    /**
     * Returns who created this token when.
     */
    @JsonProperty
    public UserAndTimestamp creation() {
        return creation;
    }

    /**
     * Returns who deactivated this token when.
     */
    @Nullable
    @JsonProperty
    public UserAndTimestamp deactivation() {
        return deactivation;
    }

    /**
     * Returns who deleted this token when.
     */
    @Nullable
    @JsonProperty
    public UserAndTimestamp deletion() {
        return deletion;
    }

    /**
     * Returns whether this token is activated.
     */
    @JsonIgnore
    public boolean isActive() {
        return deactivation == null && deletion == null;
    }

    /**
     * Returns whether this token is deleted.
     */
    @JsonIgnore
    public boolean isDeleted() {
        return deletion != null;
    }

    /**
     * Returns the IP access control rules for this token.
     */
    @JsonProperty
    public List<IpAccessControlRule> ipAccessControlRules() {
        return ipAccessControlRules;
    }

    @Override
    public String toString() {
        // Do not add "secret" to prevent it from logging.
        return MoreObjects.toStringHelper(this).omitNullValues()
                          .add("appId", appId())
                          .add("isSystemAdmin", isSystemAdmin())
                          .add("allowGuestAccess", allowGuestAccess())
                          .add("creation", creation())
                          .add("deactivation", deactivation())
                          .add("deletion", deletion())
                          .add("ipAccessControlRules", ipAccessControlRules.isEmpty() ? null : ipAccessControlRules)
                          .toString();
    }

    /**
     * Returns a new {@link Token} instance without its secret.
     */
    public Token withoutSecret() {
        return new Token(appId(), isSystemAdmin(), allowGuestAccess(), creation(), deactivation(), deletion(),
                         ipAccessControlRules());
    }

    /**
     * Returns a new {@link Token} instance with the specified system admin privilege.
     * This method must be called by the token whose secret is not null.
     */
    public Token withSystemAdmin(boolean isSystemAdmin) {
        if (isSystemAdmin == isSystemAdmin()) {
            return this;
        }
        final String secret = secret();
        assert secret != null;
        return new Token(appId(), secret, null, isSystemAdmin, allowGuestAccess(), creation(),
                         deactivation(), deletion(), ipAccessControlRules());
    }
}
