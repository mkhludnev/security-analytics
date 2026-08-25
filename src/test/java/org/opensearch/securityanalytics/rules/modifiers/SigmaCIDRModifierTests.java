/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.modifiers;

import org.junit.Assert;
import org.opensearch.securityanalytics.rules.exceptions.SigmaModifierError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaTypeError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaValueError;
import org.opensearch.securityanalytics.rules.types.SigmaCIDRExpression;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.types.SigmaType;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.Collections;
import java.util.List;

public class SigmaCIDRModifierTests extends SigmaModifierTests {

    public void testCidr() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.0/24")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("192.168.1.0/24", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrIPv4NoPrefix() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.1")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("192.168.1.1", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrIPv6() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("2001:db8::/32")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("2001:db8::/32", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrIPv6NoPrefix() throws SigmaRegularExpressionError, SigmaValueError, SigmaModifierError {
        List<SigmaType> values = new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("2001:db8::1")));
        Assert.assertTrue(values.get(0) instanceof SigmaCIDRExpression);
        Assert.assertEquals("2001:db8::1", ((SigmaCIDRExpression) values.get(0)).getCidr());
    }

    public void testCidrRejectsSignedPrefix() {
        assertThrows(SigmaTypeError.class, () ->
            new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.0/+24")))
        );
        assertThrows(SigmaTypeError.class, () ->
            new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("2001:db8::/+32")))
        );
    }

    public void testCidrRejectsWhitespaceInPrefix() {
        assertThrows(SigmaTypeError.class, () ->
            new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("192.168.1.0/24 ")))
        );
        assertThrows(SigmaTypeError.class, () ->
            new SigmaCIDRModifier(dummyDetectionItem(), Collections.emptyList()).apply(Either.left(new SigmaString("2001:db8::/ 32")))
        );
    }

    public void testCidrWithOther() {
        Exception exception = assertThrows(SigmaValueError.class, () -> {
            new SigmaCIDRModifier(dummyDetectionItem(), List.of(SigmaBase64Modifier.class)).apply(Either.left(new SigmaString("192.168.1.0/24")));
        });

        String expectedMessage = "CIDR expression modifier only applicable to unmodified values";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }
}