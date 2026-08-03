/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import com.google.common.net.InetAddresses;
import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;

import java.net.Inet6Address;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SigmaCIDRExpression implements SigmaType {
    private String cidr;

    public SigmaCIDRExpression(String cidr) throws SigmaTypeError {
        this.cidr = cidr;

        if (!isIPv4AddressValid(this.cidr) && !isIPv6AddressValid(this.cidr)) {
            throw new SigmaTypeError("Invalid CIDR expression");
        }
    }

    public String convert() {
        return this.cidr;
    }

    private static boolean isIPv4AddressValid(String cidr) {
        if (cidr == null) {
            return false;
        }

        String[] values = cidr.split("/");
        Pattern ipv4Pattern = Pattern
                .compile("(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])");
        Matcher mm = ipv4Pattern.matcher(values[0]);
        if (!mm.matches()) {
            return false;
        }
        if (values.length >= 2) {
            try {
                int prefix = Integer.parseInt(values[1]);
                if ((prefix < 0) || (prefix > 32)) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private static boolean isIPv6AddressValid(String cidr) {
        if (cidr == null) {
            return false;
        }

        // IPv6 addresses with a zone ID (e.g. fe80::1%eth0) are not valid CIDR notation
        int slashIndex = cidr.indexOf('/');
        String ipPart = slashIndex >= 0 ? cidr.substring(0, slashIndex) : cidr;

        if (!ipPart.contains(":")) {
            return false;
        }

        try {
            if (!(InetAddresses.forString(ipPart) instanceof Inet6Address)) {
                return false;
            }
        } catch (IllegalArgumentException e) {
            return false;
        }

        if (slashIndex >= 0) {
            try {
                int prefix = Integer.parseInt(cidr.substring(slashIndex + 1));
                if ((prefix < 0) || (prefix > 128)) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    public String getCidr() {
        return cidr;
    }
}