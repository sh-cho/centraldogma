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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

import javax.annotation.Nullable;

import com.google.common.net.InetAddresses;

/**
 * Utility class for IP access control operations.
 */
public final class IpAccessControlUtils {

    private IpAccessControlUtils() {}

    /**
     * Validates and normalizes a CIDR notation string.
     *
     * @param cidr the CIDR notation string to validate
     * @return the normalized CIDR string
     * @throws IllegalArgumentException if the CIDR notation is invalid
     */
    public static String validateCidr(String cidr) {
        requireNonNull(cidr, "cidr");
        
        final String trimmedCidr = cidr.trim();
        if (trimmedCidr.isEmpty()) {
            throw new IllegalArgumentException("CIDR cannot be empty");
        }

        // Handle single IP addresses without subnet mask
        if (!trimmedCidr.contains("/")) {
            // Validate the IP address
            try {
                final InetAddress addr = InetAddresses.forString(trimmedCidr);
                // Add appropriate subnet mask for single IP
                final int prefixLength = addr.getAddress().length == 4 ? 32 : 128; // IPv4 or IPv6
                return trimmedCidr + "/" + prefixLength;
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid IP address: " + trimmedCidr, e);
            }
        }

        final String[] parts = trimmedCidr.split("/", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid CIDR format: " + trimmedCidr);
        }

        final String ipPart = parts[0];
        final String prefixLengthPart = parts[1];

        // Validate IP address
        final InetAddress addr;
        try {
            addr = InetAddresses.forString(ipPart);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid IP address in CIDR: " + ipPart, e);
        }

        // Validate prefix length
        final int prefixLength;
        try {
            prefixLength = Integer.parseInt(prefixLengthPart);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid prefix length in CIDR: " + prefixLengthPart, e);
        }

        final int maxPrefixLength = addr.getAddress().length == 4 ? 32 : 128; // IPv4 or IPv6
        if (prefixLength < 0 || prefixLength > maxPrefixLength) {
            throw new IllegalArgumentException(
                    "Invalid prefix length " + prefixLength + " for " + 
                    (maxPrefixLength == 32 ? "IPv4" : "IPv6") + " address: " + ipPart);
        }

        return ipPart + "/" + prefixLength;
    }

    /**
     * Checks if an IP address matches a CIDR range.
     *
     * @param ipAddress the IP address to check
     * @param cidr the CIDR notation to match against
     * @return true if the IP address is within the CIDR range
     */
    public static boolean matchesCidr(String ipAddress, String cidr) {
        requireNonNull(ipAddress, "ipAddress");
        requireNonNull(cidr, "cidr");

        try {
            final InetAddress addr = InetAddresses.forString(ipAddress);
            return matchesCidr(addr, cidr);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Checks if an IP address matches a CIDR range.
     *
     * @param ipAddress the IP address to check
     * @param cidr the CIDR notation to match against  
     * @return true if the IP address is within the CIDR range
     */
    public static boolean matchesCidr(InetAddress ipAddress, String cidr) {
        requireNonNull(ipAddress, "ipAddress");
        requireNonNull(cidr, "cidr");

        final String[] parts = cidr.split("/", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid CIDR format: " + cidr);
        }

        final InetAddress networkAddr;
        final int prefixLength;
        try {
            networkAddr = InetAddresses.forString(parts[0]);
            prefixLength = Integer.parseInt(parts[1]);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid CIDR: " + cidr, e);
        }

        // Check if both addresses are the same type (IPv4 or IPv6)
        final byte[] addrBytes = ipAddress.getAddress();
        final byte[] networkBytes = networkAddr.getAddress();
        if (addrBytes.length != networkBytes.length) {
            return false;
        }

        // Calculate number of bytes and bits to check
        final int bytesToCheck = prefixLength / 8;
        final int remainingBits = prefixLength % 8;

        // Check full bytes
        for (int i = 0; i < bytesToCheck; i++) {
            if (addrBytes[i] != networkBytes[i]) {
                return false;
            }
        }

        // Check remaining bits if any
        if (remainingBits > 0 && bytesToCheck < addrBytes.length) {
            final int mask = 0xFF << (8 - remainingBits);
            final int addrByte = addrBytes[bytesToCheck] & 0xFF;
            final int networkByte = networkBytes[bytesToCheck] & 0xFF;
            return (addrByte & mask) == (networkByte & mask);
        }

        return true;
    }

    /**
     * Evaluates IP access control rules for a given IP address.
     * Rules are evaluated in order, and the first matching rule determines the result.
     * If no rules match, access is allowed by default.
     *
     * @param ipAddress the IP address to evaluate
     * @param rules the list of access control rules
     * @return true if access should be allowed, false if denied
     */
    public static boolean evaluateIpAccessRules(String ipAddress, @Nullable List<IpAccessControlRule> rules) {
        if (rules == null || rules.isEmpty()) {
            return true; // No rules means allow all
        }

        requireNonNull(ipAddress, "ipAddress");

        for (final IpAccessControlRule rule : rules) {
            if (matchesCidr(ipAddress, rule.cidr())) {
                return rule.action() == IpAccessControlRule.Action.ALLOW;
            }
        }

        return true; // No matching rule, allow by default
    }

    /**
     * Evaluates IP access control rules for a given IP address.
     *
     * @param ipAddress the IP address to evaluate
     * @param rules the list of access control rules
     * @return true if access should be allowed, false if denied
     */
    public static boolean evaluateIpAccessRules(InetAddress ipAddress, @Nullable List<IpAccessControlRule> rules) {
        if (rules == null || rules.isEmpty()) {
            return true; // No rules means allow all
        }

        requireNonNull(ipAddress, "ipAddress");

        for (final IpAccessControlRule rule : rules) {
            if (matchesCidr(ipAddress, rule.cidr())) {
                return rule.action() == IpAccessControlRule.Action.ALLOW;
            }
        }

        return true; // No matching rule, allow by default
    }
}