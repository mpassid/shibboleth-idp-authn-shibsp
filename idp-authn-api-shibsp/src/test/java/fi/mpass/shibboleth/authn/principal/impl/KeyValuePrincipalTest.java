/*
 * The MIT License
 * Copyright (c) 2015 CSC - IT Center for Science, http://www.csc.fi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package fi.mpass.shibboleth.authn.principal.impl;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.principal.impl.KeyValuePrincipal;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/**
 * Unit tests for classes extending {@link KeyValuePrincipal}.
 */
public abstract class KeyValuePrincipalTest {
    
    /** The key part of the pair. */
    protected String key;
    
    /** The value part of the pair. */
    protected String value;
    
    /** The class implementing the principal. */
    protected Class<? extends KeyValuePrincipal> principalClass;
    
    /**
     * Init tests.
     */
    @BeforeTest public void initTests() {
        key = "mockKey";
        value = "mockValue";
        initPrincipalClass();
    }
    
    /**
     * The method for setting principalClass variable with the class to be tested.
     */
    public abstract void initPrincipalClass();
    
    /**
     * Attempts to initialize the principal with invalid name.
     */
    @Test public void testInvalidNameInit() throws Exception {
        Assert.assertTrue(testInvalidNameInit("invalid"));
    }
    
    /**
     * Compares key and value after successful name initialization.
     */
    @Test public void testValidNameInit() throws Exception {
        Constructor<? extends KeyValuePrincipal> constructor = principalClass.getDeclaredConstructor(String.class);
        KeyValuePrincipal principal = constructor.newInstance(key + KeyValuePrincipal.SEPARATOR + value);
        assertKeyAndValue(principal);
    }
    
    /**
     * Attempts to initialize the principal with null name.
     */
    @Test public void testNullNameInit() throws Exception {
        Assert.assertTrue(testInvalidNameInit(null));        
    }

    /**
     * Attempts to initialize the principal with empty name.
     */
    @Test public void testEmptyNameInit() throws Exception {
        Assert.assertTrue(testInvalidNameInit(""));        
    }

    /**
     * Attempts to initialize the principal with null key.
     */
    @Test public void testNullKeyInit() throws Exception {
        Assert.assertTrue(testInvalidKeyOrValueInit(null, value));    
    }

    /**
     * Attempts to initialize the principal with empty key.
     */
    @Test public void testEmptyKeyInit() throws Exception {
        Assert.assertTrue(testInvalidKeyOrValueInit("", value));    
    }

    /**
     * Attempts to initialize the principal with null value.
     */
    @Test public void testNullValueInit() throws Exception {
        Assert.assertTrue(testInvalidKeyOrValueInit(key, null));    
    }

    /**
     * Attempts to initialize the principal with empty value.
     */
    @Test public void testEmptyValueInit() throws Exception {
        Assert.assertTrue(testInvalidKeyOrValueInit(key, null));    
    }
    
    /**
     * Tests that key and value exists in toString.
     */
    @Test public void testToString() throws Exception {
        Constructor<? extends KeyValuePrincipal> constructor = principalClass.getDeclaredConstructor(String.class);
        KeyValuePrincipal principal = constructor.newInstance(key + KeyValuePrincipal.SEPARATOR + value);
        Assert.assertTrue(principal.toString().contains(key));
        Assert.assertTrue(principal.toString().contains(value));
    }

    /**
     * Compares key and value after successful initialization.
     */    
    @Test public void testValidKeyValueInit() throws Exception {
        Constructor<? extends KeyValuePrincipal> constructor = principalClass.getDeclaredConstructor(String.class, String.class);
        KeyValuePrincipal principal = constructor.newInstance(key, value);
        assertKeyAndValue(principal);
    }
    
    /**
     * Attempts to initialize the principalClass object with invalid name.
     * @param name
     * @return
     * @throws Exception
     */
    protected boolean testInvalidNameInit(String name) throws Exception {
        Constructor<? extends KeyValuePrincipal> constructor = principalClass.getDeclaredConstructor(String.class);
        try {
            constructor.newInstance(name);
        } catch (ConstraintViolationException | InvocationTargetException e) {
            return true;
        }
        return false;
    }
    
    /**
     * Attempts to initialize the principalClass object with invalid key or value.
     * @param key
     * @param value
     * @return
     * @throws Exception
     */
    protected boolean testInvalidKeyOrValueInit(String key, String value) throws Exception {
        Constructor<? extends KeyValuePrincipal> constructor = principalClass.getDeclaredConstructor(String.class, String.class);
        try {
            constructor.newInstance(key, value);
        } catch (ConstraintViolationException | InvocationTargetException e) {
            return true;
        }
        return false;
    }
    
    /**
     * Verifies that the key and value are as expected.
     * @param principal
     */
    protected void assertKeyAndValue(final KeyValuePrincipal principal) {
        Assert.assertEquals(principal.getKey(), key);
        Assert.assertEquals(principal.getValue(), value);
        Assert.assertEquals(principal.getName(), key + KeyValuePrincipal.SEPARATOR + value);
    }
}