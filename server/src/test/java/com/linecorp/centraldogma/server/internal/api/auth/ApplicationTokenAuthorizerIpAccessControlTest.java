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

package com.linecorp.centraldogma.server.internal.api.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Collections;
import java.util.concurrent.CompletionStage;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.linecorp.armeria.common.HttpRequest;
import com.linecorp.armeria.server.ServiceRequestContext;
import com.linecorp.centraldogma.server.metadata.IpAccessControlRule;
import com.linecorp.centraldogma.server.metadata.Token;
import com.linecorp.centraldogma.server.metadata.UserAndTimestamp;

class ApplicationTokenAuthorizerIpAccessControlTest {

    private static final String VALID_TOKEN = "appToken-12345-67890-abcde-fghij-klmno";
    private static final String APP_ID = "test-app";
    
    private ApplicationTokenAuthorizer authorizer;
    private ServiceRequestContext ctx;
    private HttpRequest req;

    @BeforeEach
    void setUp() {
        ctx = mock(ServiceRequestContext.class);
        req = mock(HttpRequest.class);
    }

    @Test
    void shouldAllowAccessWhenNoIpRestrictionsConfigured() throws Exception {
        // Token with no IP access control rules
        Token token = createToken(Collections.emptyList());
        authorizer = new ApplicationTokenAuthorizer(secret -> token);

        // Mock client from allowed IP
        when(ctx.remoteAddress()).thenReturn(new InetSocketAddress("192.168.1.10", 8080));
        mockContextForSuccessfulAuth();

        CompletionStage<Boolean> result = authorizer.authorize(ctx, req, VALID_TOKEN);
        assertThat(result.toCompletableFuture().get()).isTrue();
    }

    @Test
    void shouldAllowAccessWhenClientIpIsInAllowedRange() throws Exception {
        // Token with ALLOW rule for internal network
        Token token = createToken(Arrays.asList(
            new IpAccessControlRule(IpAccessControlRule.Action.ALLOW, "192.168.1.0/24", "Internal network")
        ));
        authorizer = new ApplicationTokenAuthorizer(secret -> token);

        // Mock client from allowed IP
        when(ctx.remoteAddress()).thenReturn(new InetSocketAddress("192.168.1.10", 8080));
        mockContextForSuccessfulAuth();

        CompletionStage<Boolean> result = authorizer.authorize(ctx, req, VALID_TOKEN);
        assertThat(result.toCompletableFuture().get()).isTrue();
    }

    @Test
    void shouldDenyAccessWhenClientIpIsInDeniedRange() throws Exception {
        // Token with DENY rule for external network
        Token token = createToken(Arrays.asList(
            new IpAccessControlRule(IpAccessControlRule.Action.DENY, "192.168.1.0/24", "Block internal")
        ));
        authorizer = new ApplicationTokenAuthorizer(secret -> token);

        // Mock client from denied IP
        when(ctx.remoteAddress()).thenReturn(new InetSocketAddress("192.168.1.10", 8080));

        CompletionStage<Boolean> result = authorizer.authorize(ctx, req, VALID_TOKEN);
        assertThat(result.toCompletableFuture().get()).isFalse();
    }

    @Test
    void shouldAllowAccessWhenClientIpDoesNotMatchAnyRule() throws Exception {
        // Token with specific IP restriction
        Token token = createToken(Arrays.asList(
            new IpAccessControlRule(IpAccessControlRule.Action.DENY, "10.0.0.0/8", "Block internal 10.x")
        ));
        authorizer = new ApplicationTokenAuthorizer(secret -> token);

        // Mock client from IP that doesn't match any rule (should default to allow)
        when(ctx.remoteAddress()).thenReturn(new InetSocketAddress("192.168.1.10", 8080));
        mockContextForSuccessfulAuth();

        CompletionStage<Boolean> result = authorizer.authorize(ctx, req, VALID_TOKEN);
        assertThat(result.toCompletableFuture().get()).isTrue();
    }

    @Test
    void shouldRespectRuleOrderingForFirstMatchWins() throws Exception {
        // Token with multiple rules - first match should win
        Token token = createToken(Arrays.asList(
            new IpAccessControlRule(IpAccessControlRule.Action.DENY, "192.168.1.10/32", "Block specific IP"),
            new IpAccessControlRule(IpAccessControlRule.Action.ALLOW, "192.168.1.0/24", "Allow network")
        ));
        authorizer = new ApplicationTokenAuthorizer(secret -> token);

        // Mock client from IP that matches first rule (DENY)
        when(ctx.remoteAddress()).thenReturn(new InetSocketAddress("192.168.1.10", 8080));

        CompletionStage<Boolean> result = authorizer.authorize(ctx, req, VALID_TOKEN);
        assertThat(result.toCompletableFuture().get()).isFalse();
    }

    @Test
    void shouldAllowWhenFirstRuleIsAllow() throws Exception {
        // Token with ALLOW rule first, then DENY rule
        Token token = createToken(Arrays.asList(
            new IpAccessControlRule(IpAccessControlRule.Action.ALLOW, "192.168.1.0/24", "Allow network first"),
            new IpAccessControlRule(IpAccessControlRule.Action.DENY, "192.168.1.10/32", "Block specific IP")
        ));
        authorizer = new ApplicationTokenAuthorizer(secret -> token);

        // Mock client from IP that matches first rule (ALLOW)
        when(ctx.remoteAddress()).thenReturn(new InetSocketAddress("192.168.1.10", 8080));
        mockContextForSuccessfulAuth();

        CompletionStage<Boolean> result = authorizer.authorize(ctx, req, VALID_TOKEN);
        assertThat(result.toCompletableFuture().get()).isTrue();
    }

    @Test
    void shouldDenyAccessForInactiveToken() throws Exception {
        // Create inactive token
        Token token = createInactiveToken();
        authorizer = new ApplicationTokenAuthorizer(secret -> token);

        when(ctx.remoteAddress()).thenReturn(new InetSocketAddress("192.168.1.10", 8080));

        CompletionStage<Boolean> result = authorizer.authorize(ctx, req, VALID_TOKEN);
        assertThat(result.toCompletableFuture().get()).isFalse();
    }

    @Test
    void shouldDenyAccessForNullToken() throws Exception {
        authorizer = new ApplicationTokenAuthorizer(secret -> null);

        when(ctx.remoteAddress()).thenReturn(new InetSocketAddress("192.168.1.10", 8080));

        CompletionStage<Boolean> result = authorizer.authorize(ctx, req, VALID_TOKEN);
        assertThat(result.toCompletableFuture().get()).isFalse();
    }

    @Test
    void shouldHandleNonInetSocketAddress() throws Exception {
        // Token with IP restrictions
        Token token = createToken(Arrays.asList(
            new IpAccessControlRule(IpAccessControlRule.Action.DENY, "0.0.0.0/0", "Block all")
        ));
        authorizer = new ApplicationTokenAuthorizer(secret -> token);

        // Mock non-InetSocketAddress (should skip IP checking and allow)
        when(ctx.remoteAddress()).thenReturn(() -> "unix-socket");
        mockContextForSuccessfulAuth();

        CompletionStage<Boolean> result = authorizer.authorize(ctx, req, VALID_TOKEN);
        assertThat(result.toCompletableFuture().get()).isTrue();
    }

    private Token createToken(java.util.List<IpAccessControlRule> ipAccessControlRules) {
        return new Token(APP_ID, VALID_TOKEN, null, false, true,
                         UserAndTimestamp.of("test-user"), null, null, ipAccessControlRules);
    }

    private Token createInactiveToken() {
        return new Token(APP_ID, VALID_TOKEN, null, false, true,
                         UserAndTimestamp.of("test-user"),
                         UserAndTimestamp.of("test-user"), // deactivated
                         null, Collections.emptyList());
    }

    private void mockContextForSuccessfulAuth() {
        // Mock the context methods called during successful authentication
        when(ctx.logBuilder()).thenReturn(mock(com.linecorp.armeria.common.logging.RequestLogBuilder.class));
        when(ctx.logBuilder().authenticatedUser("app/" + APP_ID))
                .thenReturn(mock(com.linecorp.armeria.common.logging.RequestLogBuilder.class));
    }
}