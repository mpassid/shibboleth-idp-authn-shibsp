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

import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.principal.impl.KeyValuePrincipal;
import fi.mpass.shibboleth.authn.principal.impl.ShibAttributePrincipal;
import fi.mpass.shibboleth.authn.principal.impl.ShibHeaderPrincipal;

/**
 * Unit testing for {@link ShibAttributePrincipal}.
 */
public class ShibAttributePrincipalTest extends KeyValuePrincipalTest {
    
    @Override @BeforeTest @Test
    public void initTests() {
        super.initTests();
        principalClass = ShibAttributePrincipal.class;
    }

    @Override
    public void initPrincipalClass() {
        principalClass = ShibAttributePrincipal.class;
    }
    
    @Test
    public void testClone() throws Exception {
        super.assertKeyAndValue(new ShibAttributePrincipal(key, value).clone());
    }
    
    @Test
    public void testEquals() throws Exception {
        ShibAttributePrincipal principal1 = new ShibAttributePrincipal(key, value);
        Object principal2 = new ShibAttributePrincipal(key + KeyValuePrincipal.SEPARATOR + value);
        Object principal3 = new ShibAttributePrincipal(key + "mock", value);
        Object principal4 = new ShibAttributePrincipal(key, "mock" + value);
        ShibHeaderPrincipal principal5 = new ShibHeaderPrincipal(key, value);
        Assert.assertTrue(principal1.equals(principal1));
        Assert.assertTrue(principal1.equals(principal2));
        Assert.assertFalse(principal1.equals(null));
        Assert.assertFalse(principal1.equals(principal3));
        Assert.assertFalse(principal1.equals(principal4));
        Assert.assertFalse(principal1.equals(principal5));
    }
    
    @Test
    public void testHash() throws Exception {
        ShibAttributePrincipal principal1 = new ShibAttributePrincipal(key, value);
        ShibAttributePrincipal principal2 = new ShibAttributePrincipal(key + KeyValuePrincipal.SEPARATOR + value);
        ShibAttributePrincipal principal3 = new ShibAttributePrincipal(key, "mock" + value);
        Assert.assertEquals(principal1.hashCode(), principal2.hashCode());
        Assert.assertFalse(principal1.hashCode() == principal3.hashCode());
    }
}