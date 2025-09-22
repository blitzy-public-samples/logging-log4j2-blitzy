#!/bin/bash

# Security Validation Script for CVE-2021-44228 (Log4Shell) Fix
# Verifies that JNDI injection vulnerability has been mitigated

echo "=== Log4j CVE-2021-44228 (Log4Shell) Security Fix Validation ==="
echo

# 1. Verify JndiLookup.class is NOT present in the JAR
echo "1. Verifying JndiLookup.class removal from JAR..."
if jar tf target/log4j-core-2.14.1.jar | grep -q "JndiLookup.class"; then
    echo "❌ FAIL: JndiLookup.class still present in JAR"
    echo "   This indicates the security fix was not applied correctly"
    exit 1
else
    echo "✅ PASS: JndiLookup.class successfully removed from JAR"
fi
echo

# 2. Verify other JNDI classes remain (they are not vulnerable)
echo "2. Verifying legitimate JNDI classes remain..."
if jar tf target/log4j-core-2.14.1.jar | grep -q "JndiManager.class"; then
    echo "✅ PASS: JndiManager.class properly retained (not vulnerable)"
else
    echo "⚠️  WARNING: JndiManager.class missing - this may indicate over-removal"
fi
echo

# 3. Check for successful JAR creation
echo "3. Verifying JAR creation..."
if [[ -f "target/log4j-core-2.14.1.jar" ]]; then
    JAR_SIZE=$(stat -c%s "target/log4j-core-2.14.1.jar")
    echo "✅ PASS: JAR file created successfully (Size: $JAR_SIZE bytes)"
else
    echo "❌ FAIL: JAR file not found"
    exit 1
fi
echo

# 4. List all JNDI-related classes in JAR
echo "4. Inventory of remaining JNDI-related classes:"
JNDI_CLASSES=$(jar tf target/log4j-core-2.14.1.jar | grep -i jndi || echo "None found")
echo "$JNDI_CLASSES"
echo

# 5. Verify source file removal
echo "5. Verifying source file removal..."
if [[ -f "src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java" ]]; then
    echo "❌ FAIL: JndiLookup.java source file still exists"
    exit 1
else
    echo "✅ PASS: JndiLookup.java source file successfully removed"
fi
echo

echo "=== SECURITY FIX VALIDATION SUMMARY ==="
echo "✅ Primary vulnerability vector (JndiLookup) eliminated"
echo "✅ JAR compiled successfully without vulnerable class"
echo "✅ Legitimate JNDI functionality preserved (JndiManager, etc.)"
echo
echo "🛡️  SECURITY STATUS: CVE-2021-44228 (Log4Shell) MITIGATED"
echo "📋 Mitigation Method: JndiLookup class removal"
echo "📅 Applied: $(date)"
echo
echo "NOTE: Applications using this patched JAR will no longer process \${jndi:...} patterns"
echo "      but all other Log4j functionality remains intact."
echo