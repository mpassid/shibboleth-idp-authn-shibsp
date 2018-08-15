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

import java.io.IOException;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.principal.impl.ShibAttributePrincipal;
import fi.mpass.shibboleth.authn.principal.impl.ShibAttributePrincipalSerializer;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;

/**
 * Unit tests for {@link ShibAttributePrincipalSerializer}.
 */
public class ShibAttributePrincipalSerializerTest {

    ShibAttributePrincipalSerializer serializer;
    
    String key;
    
    String value;
    
    @BeforeMethod
    public void initTests() {
        serializer = new ShibAttributePrincipalSerializer();
        key = "mockKey";
        value = "mockValue";
    }

    @Test
    public void testSupports() throws IOException {
        Assert.assertTrue(serializer.supports(new ShibAttributePrincipal(key, value)));
        Assert.assertFalse(serializer.supports(new UsernamePrincipal(key)));
        Assert.assertTrue(serializer.supports(serializer.serialize(new ShibAttributePrincipal(key, value))));
        Assert.assertFalse(serializer.supports("{ \"mock\":\"mock\""));
    }

    @Test
    public void testUnmatch() throws IOException {
        final ShibAttributePrincipal principal = new ShibAttributePrincipal("userId", "mock" + key);
        final ShibAttributePrincipal serialized = serializer.deserialize(serializer.serialize(principal));
        Assert.assertNotEquals(serialized.getKey(), key);
        Assert.assertNotEquals(serialized.getValue(), value);
    }
    
    @Test
    public void testMatch() throws IOException {
        final ShibAttributePrincipal principal = new ShibAttributePrincipal(key, value);
        final ShibAttributePrincipal serialized = serializer.deserialize(serializer.serialize(principal));
        Assert.assertEquals(serialized.getKey(), key);
        Assert.assertEquals(serialized.getValue(), value);        
    }
}
