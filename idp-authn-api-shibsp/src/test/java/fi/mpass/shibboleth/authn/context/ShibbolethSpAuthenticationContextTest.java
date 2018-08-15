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

package fi.mpass.shibboleth.authn.context;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.testng.Assert;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;

/**
 * Unit tests for {@link ShibbolethSpAuthenticationContext}.
 */
public class ShibbolethSpAuthenticationContextTest {

    /** The IdP who authenticated the user. */
    private String idp;

    /** The authentication instant when user was authenticated at the IdP. */
    private String instant;

    /** The authentication method how user was authenticated at the IdP. */
    private String method;

    /** The authentication context class how user was authenticated at the IdP. */
    private String contextClass;
    
    /** The authentication context declaration how user was authenticated at the IdP. */
    private String contextDecl;
    
    /** The initial authentication context requested from this IdP. */
    private List<Principal> initialRequestedContext;
    
    /** The mapped authentication context to be requested from the authenticating IdP. */
    private List<Principal> mappedAuthnContext;

    /**
     * Initializes variables.
     */
    @BeforeTest
    public void initTest() {
        idp = "mockIdp";
        instant = "mockInstant";
        method = "mockMethod";
        contextClass = "mockContextClass";
        contextDecl = "mockContextDecl";
        initialRequestedContext = new ArrayList<>();
        mappedAuthnContext = new ArrayList<>();
    }

    /**
     * Tests header map.
     */
    @Test
    public void testHeaders() {
        final ShibbolethSpAuthenticationContext shibCtx = new ShibbolethSpAuthenticationContext();
        Assert.assertNotNull(shibCtx.getHeaders());
        Assert.assertTrue(shibCtx.getHeaders().isEmpty());
        Assert.assertEquals(shibCtx.getHeaders().size(), 0);

        final Map<String, String> headers = new HashMap<String, String>();
        headers.put("mockKey", "mockValue");
        shibCtx.setHeaders(headers);

        Assert.assertEquals(shibCtx.getHeaders().size(), 1);
    }

    /**
     * Tests attribute map.
     */
    @Test
    public void testAttributes() {
        final ShibbolethSpAuthenticationContext shibCtx = new ShibbolethSpAuthenticationContext();
        Assert.assertNotNull(shibCtx.getAttributes());
        Assert.assertTrue(shibCtx.getAttributes().isEmpty());
        Assert.assertEquals(shibCtx.getAttributes().size(), 0);

        final Map<String, String> attributes = new HashMap<String, String>();
        attributes.put("mockKey", "mockValue");
        shibCtx.setAttributes(attributes);

        Assert.assertEquals(shibCtx.getAttributes().size(), 1);
    }

    /**
     * Tests setters and getters.
     */
    @Test
    public void testSetGet() {
        final ShibbolethSpAuthenticationContext shibCtx = new ShibbolethSpAuthenticationContext();
        Assert.assertNull(shibCtx.getIdp());
        Assert.assertNull(shibCtx.getInstant());
        Assert.assertNull(shibCtx.getMethod());
        Assert.assertNull(shibCtx.getContextClass());
        Assert.assertNull(shibCtx.getContextDecl());
        Assert.assertNull(shibCtx.getInitialRequestedContext());
        Assert.assertNull(shibCtx.getMappedAuthnContext());
        shibCtx.setIdp(idp);
        Assert.assertEquals(shibCtx.getIdp(), idp);
        shibCtx.setInstant(instant);
        Assert.assertEquals(shibCtx.getInstant(), instant);
        shibCtx.setMethod(method);
        Assert.assertEquals(shibCtx.getMethod(), method);
        shibCtx.setContextClass(contextClass);
        Assert.assertEquals(shibCtx.getContextClass(), contextClass);
        shibCtx.setContextDecl(contextDecl);
        Assert.assertEquals(shibCtx.getContextDecl(), contextDecl);
        initialRequestedContext.add(new AuthnContextClassRefPrincipal("mockRequested"));
        shibCtx.setInitialRequestedContext(initialRequestedContext);
        Assert.assertEquals(shibCtx.getInitialRequestedContext(), initialRequestedContext);
        mappedAuthnContext.add(new AuthnContextClassRefPrincipal("mockMapped"));
        shibCtx.setMappedAuthnContext(mappedAuthnContext);
        Assert.assertEquals(shibCtx.getMappedAuthnContext(), mappedAuthnContext);
    }
}
