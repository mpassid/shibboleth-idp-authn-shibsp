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

package fi.mpass.shibboleth.authn.impl;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletConfig;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import fi.mpass.shibboleth.authn.impl.ShibbolethSpAuthnServlet;
import fi.mpass.shibboleth.authn.principal.impl.ShibHeaderPrincipal;
import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.ExternalAuthenticationContext;
import net.shibboleth.idp.authn.impl.BaseAuthenticationContextTest;
import net.shibboleth.idp.authn.impl.ExternalAuthenticationImpl;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;

/**
 * Unit tests for {@link ShibbolethSpAuthnServlet}.
 */
public class ShibbolethSpAuthnServletTest extends BaseAuthenticationContextTest {
    
    /** The servlet to be tested. */
    ShibbolethSpAuthnServlet servlet;
    
    /** The conversation key. */
    String conversationKey;
    
    /** The flow execution URL. */
    String flowExecutionUrl;
    
    @BeforeMethod
    public void initTests() throws Exception {
        super.setUp();
        servlet = new ShibbolethSpAuthnServlet();
        servlet.init(new MockServletConfig());
        conversationKey = "mockKey";
        flowExecutionUrl = "http://localhost/mock";
        final AuthenticationContext authnContext = prc.getSubcontext(AuthenticationContext.class, false);
        authnContext.setAttemptedFlow(authenticationFlows.get(0));
        final ExternalAuthenticationContext extContext = authnContext.getSubcontext(ExternalAuthenticationContext.class, true);
        extContext.setFlowExecutionUrl(flowExecutionUrl);
    }
    
    @Test
    public void testEmptyRequest() throws Exception {
        final MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        final MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        servlet.doGet(servletRequest, servletResponse);
        Assert.assertNull(servletResponse.getRedirectedUrl());
        final AuthenticationContext authnContext = prc.getSubcontext(AuthenticationContext.class, false);
        final ExternalAuthenticationContext extContext = authnContext.getSubcontext(ExternalAuthenticationContext.class, true);
        Assert.assertNull(extContext.getSubject());
    }
    
    @Test
    public void testWithoutHeaders() throws Exception {
        final MockHttpServletRequest servletRequest = initServletRequest();
        final MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        servlet.doGet(servletRequest, servletResponse);
        Assert.assertEquals(servletResponse.getRedirectedUrl(), flowExecutionUrl);
        assertExternalContext(null, null, null);
    }

    @Test
    public void testWithRemoteUser() throws Exception {
        final MockHttpServletRequest servletRequest = initServletRequest();
        final String username = "mockUser";
        servletRequest.setRemoteUser(username);
        final MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        servlet.doGet(servletRequest, servletResponse);
        Assert.assertEquals(servletResponse.getRedirectedUrl(), flowExecutionUrl);
        assertExternalContext(null, null, username);
    }

    @Test
    public void testWithHeaders() throws Exception {
        final MockHttpServletRequest servletRequest = initServletRequest();
        final String headerName = "mockHeader";
        final String headerValue = "mockValue";
        servletRequest.addHeader(headerName, headerValue);
        servletRequest.addHeader(headerName + "2", "");
        final MockHttpServletResponse servletResponse = new MockHttpServletResponse();
        servlet.doGet(servletRequest, servletResponse);
        Assert.assertEquals(servletResponse.getRedirectedUrl(), flowExecutionUrl);
        assertExternalContext(headerName, headerValue, null);
    }
    
    protected void assertExternalContext(final String shibName, final String shibValue, final String username) {
        final AuthenticationContext authnContext = prc.getSubcontext(AuthenticationContext.class, false);
        final ExternalAuthenticationContext extContext = authnContext.getSubcontext(ExternalAuthenticationContext.class, true);
        Assert.assertNotNull(extContext.getSubject());
        if (shibName == null) {
            Assert.assertEquals(extContext.getSubject().getPrincipals(ShibHeaderPrincipal.class).size(), 0);
        } else {
            Assert.assertEquals(extContext.getSubject().getPrincipals(ShibHeaderPrincipal.class).size(), 1);            
            final ShibHeaderPrincipal principal = extContext.getSubject().getPrincipals(ShibHeaderPrincipal.class).iterator().next();
            Assert.assertEquals(principal.getKey(), shibName);
            Assert.assertEquals(principal.getValue(), shibValue);
       }
        if (username == null) {
            Assert.assertEquals(extContext.getSubject().getPrincipals(UsernamePrincipal.class).size(), 0);
        } else {
            Assert.assertEquals(extContext.getSubject().getPrincipals(UsernamePrincipal.class).size(), 1);
            final UsernamePrincipal principal = extContext.getSubject().getPrincipals(UsernamePrincipal.class).iterator().next();
            Assert.assertEquals(principal.getName(), username);            
        }
    }
    
    protected MockHttpServletRequest initServletRequest() {
        final MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        final MockHttpSession session = new MockHttpSession();
        servletRequest.setParameter(ExternalAuthentication.CONVERSATION_KEY, conversationKey);
        session.setAttribute(ExternalAuthentication.CONVERSATION_KEY + conversationKey, new ExternalAuthenticationImpl(prc));
        servletRequest.setSession(session);
        return servletRequest;
    }
}