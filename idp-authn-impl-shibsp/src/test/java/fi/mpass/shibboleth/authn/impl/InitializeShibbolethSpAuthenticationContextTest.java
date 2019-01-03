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

import java.security.Principal;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import com.google.common.base.Functions;

import fi.mpass.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import fi.mpass.shibboleth.authn.impl.InitializeShibbolethSpAuthenticationContext;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.impl.BaseAuthenticationContextTest;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import net.shibboleth.idp.saml.authn.principal.AuthnContextDeclRefPrincipal;
import net.shibboleth.idp.saml.saml2.profile.SAML2ActionTestingSupport;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

/**
 * Unit tests for {@link InitializeShibbolethSpAuthenticationContext}.
 */
public class InitializeShibbolethSpAuthenticationContextTest extends BaseAuthenticationContextTest {

    /** The action to be tested. */
    private InitializeShibbolethSpAuthenticationContext action;

    /** An initial requested context class reference. */
    private String ctxClass1;

    /** An initial requested context declaration reference. */
    private String ctxDecl1;
    
    /** The mapped context class reference. */
    private String mappedCtxClass1;
    
    /** The mapped context declaration reference. */
    private String mappedCtxDecl1;

    /** {@inheritDoc} */
    @BeforeMethod
    public void setUp() throws Exception {
        super.setUp();
        InitializationService.initialize();
    }

    /**
     * Initializes the expected context variables.
     */
    @BeforeTest
    public void initTest() {
        ctxClass1 = "mockClass1";
        ctxDecl1 = "mockDecl1";
        mappedCtxClass1 = "mappedClass1";
        mappedCtxDecl1 = "mappedDecl1";
    }

    /**
     * Tests action without relying party context.
     * 
     * @throws ComponentInitializationException
     */
    @Test
    public void testNoRpCtx() throws ComponentInitializationException {
        action = new InitializeShibbolethSpAuthenticationContext();
        prc.removeSubcontext(RelyingPartyContext.class);
        action.initialize();
        Assert.assertNull(action.execute(src));
    }

    /**
     * Tests action without defined mappings or request.
     * 
     * @throws ComponentInitializationException
     */
    @SuppressWarnings("rawtypes")
    @Test
    public void testNoMappingsNoRequest() throws ComponentInitializationException {
        action = new InitializeShibbolethSpAuthenticationContext();
        action.setRelyingPartyContextLookupStrategy(new ChildContextLookup<ProfileRequestContext, RelyingPartyContext>(RelyingPartyContext.class));
        action.setAuthnRequestLookupStrategy(Functions.compose(new MessageLookup<>(AuthnRequest.class), new InboundMessageContextLookup()));
        action.initialize();
        Assert.assertNull(action.execute(src));
    }

    /**
     * Tests action without requested context.
     * 
     * @throws ComponentInitializationException
     * @throws InitializationException
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testNoRequestedContext() throws ComponentInitializationException, InitializationException {
        action = new InitializeShibbolethSpAuthenticationContext();
        final Map<String, Map<Principal, Principal>> mappings = new HashMap<>();
        prc.getInboundMessageContext().setMessage(SAML2ActionTestingSupport.buildAuthnRequest());
        action.setAuthnContextMappings(mappings);
        action.initialize();
        Assert.assertNull(action.execute(src));
        final ShibbolethSpAuthenticationContext shibSpCtx = prc.getSubcontext(AuthenticationContext.class)
                .getSubcontext(ShibbolethSpAuthenticationContext.class, false);
        Assert.assertNotNull(shibSpCtx);
        Assert.assertEquals(shibSpCtx.getInitialRequestedContext().size(), 0);
        Assert.assertEquals(shibSpCtx.getMappedAuthnContext().size(), 0);
    }
    
    /**
     * Tests action without requested context but mapped.
     * 
     * @throws ComponentInitializationException
     * @throws InitializationException
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testNoRequestedMappedContext() throws ComponentInitializationException, InitializationException {
        action = new InitializeShibbolethSpAuthenticationContext();
        final Map<String, Map<Principal, Principal>> mappings = new HashMap<>();
        final Map<Principal, Principal> rpMappings = new HashMap<>();
        rpMappings.put(null, new AuthnContextClassRefPrincipal(mappedCtxClass1));
        mappings.put(prc.getSubcontext(RelyingPartyContext.class).getRelyingPartyId(), rpMappings);
        prc.getInboundMessageContext().setMessage(SAML2ActionTestingSupport.buildAuthnRequest());
        action.setAuthnContextMappings(mappings);
        action.initialize();
        Assert.assertNull(action.execute(src));
        final ShibbolethSpAuthenticationContext shibSpCtx = prc.getSubcontext(AuthenticationContext.class)
                .getSubcontext(ShibbolethSpAuthenticationContext.class, false);
        Assert.assertNotNull(shibSpCtx);
        Assert.assertEquals(shibSpCtx.getInitialRequestedContext().size(), 0);
        final List<Principal> mappedAuthnCtx = shibSpCtx.getMappedAuthnContext();
        Assert.assertEquals(mappedAuthnCtx.size(), 1);
        Assert.assertEquals(mappedAuthnCtx.get(0).getName(), mappedCtxClass1);
    }

    /**
     * Tests action with requested context class and decl but without mappings.
     * 
     * @throws ComponentInitializationException
     * @throws InitializationException
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testNoMappings() throws ComponentInitializationException, InitializationException {
        action = new InitializeShibbolethSpAuthenticationContext();
        final Map<String, Map<Principal, Principal>> mappings = new HashMap<>();
        final AuthnRequest authnRequest = SAML2ActionTestingSupport.buildAuthnRequest();
        final RequestedAuthnContext requestedCtx = buildRequestedAuthnContext();
        requestedCtx.getAuthnContextClassRefs().add(buildContextClassRef(ctxClass1));
        requestedCtx.getAuthnContextDeclRefs().add(buildContextDeclRef(ctxDecl1));
        authnRequest.setRequestedAuthnContext(requestedCtx);
        prc.getInboundMessageContext().setMessage(authnRequest);
        action.setAuthnContextMappings(mappings);
        action.initialize();
        Assert.assertNull(action.execute(src));
        final ShibbolethSpAuthenticationContext shibSpCtx = prc.getSubcontext(AuthenticationContext.class)
                .getSubcontext(ShibbolethSpAuthenticationContext.class, false);
        Assert.assertNotNull(shibSpCtx);
        final List<Principal> initialRequestedCtx = shibSpCtx.getInitialRequestedContext();
        Assert.assertEquals(initialRequestedCtx.size(), 2);
        Assert.assertEquals(initialRequestedCtx.get(0).getName(), ctxClass1);
        Assert.assertEquals(initialRequestedCtx.get(1).getName(), ctxDecl1);
        final List<Principal> mappedAuthnCtx = shibSpCtx.getMappedAuthnContext();
        Assert.assertEquals(mappedAuthnCtx.size(), 2);
        Assert.assertEquals(mappedAuthnCtx.get(0).getName(), ctxClass1);
        Assert.assertEquals(mappedAuthnCtx.get(1).getName(), ctxDecl1);
    }
    
    /**
     * Tests action with requested context class and decl with mappings.
     * 
     * @throws ComponentInitializationException
     * @throws InitializationException
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testMappings() throws ComponentInitializationException, InitializationException {
        action = new InitializeShibbolethSpAuthenticationContext();
        final Map<String, Map<Principal, Principal>> mappings = new HashMap<>();
        final Map<Principal, Principal> rpMappings = new HashMap<>();
        rpMappings.put(new AuthnContextClassRefPrincipal(ctxClass1), new AuthnContextClassRefPrincipal(mappedCtxClass1));
        rpMappings.put(new AuthnContextDeclRefPrincipal(ctxDecl1), new AuthnContextDeclRefPrincipal(mappedCtxDecl1));
        mappings.put(prc.getSubcontext(RelyingPartyContext.class).getRelyingPartyId(), rpMappings);
        final AuthnRequest authnRequest = SAML2ActionTestingSupport.buildAuthnRequest();
        final RequestedAuthnContext requestedCtx = buildRequestedAuthnContext();
        requestedCtx.getAuthnContextClassRefs().add(buildContextClassRef(ctxClass1));
        requestedCtx.getAuthnContextDeclRefs().add(buildContextDeclRef(ctxDecl1));
        authnRequest.setRequestedAuthnContext(requestedCtx);
        prc.getInboundMessageContext().setMessage(authnRequest);
        action.setAuthnContextMappings(mappings);
        action.initialize();
        Assert.assertNull(action.execute(src));
        final ShibbolethSpAuthenticationContext shibSpCtx = prc.getSubcontext(AuthenticationContext.class)
                .getSubcontext(ShibbolethSpAuthenticationContext.class, false);
        Assert.assertNotNull(shibSpCtx);
        final List<Principal> initialRequestedCtx = shibSpCtx.getInitialRequestedContext();
        Assert.assertEquals(initialRequestedCtx.size(), 2);
        Assert.assertEquals(initialRequestedCtx.get(0).getName(), ctxClass1);
        Assert.assertEquals(initialRequestedCtx.get(1).getName(), ctxDecl1);
        final List<Principal> mappedAuthnCtx = shibSpCtx.getMappedAuthnContext();
        Assert.assertEquals(mappedAuthnCtx.size(), 2);
        Assert.assertEquals(mappedAuthnCtx.get(0).getName(), mappedCtxClass1);
        Assert.assertEquals(mappedAuthnCtx.get(1).getName(), mappedCtxDecl1);
    }

    /**
     * Helper method for building {@link RequestedAuthnContext}.
     * @return
     */
    protected static RequestedAuthnContext buildRequestedAuthnContext() {
        final SAMLObjectBuilder<RequestedAuthnContext> requestedBuilder =
                (SAMLObjectBuilder<RequestedAuthnContext>) XMLObjectProviderRegistrySupport.getBuilderFactory()
                        .<RequestedAuthnContext> getBuilderOrThrow(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
        return requestedBuilder.buildObject();
    }

    /**
     * Helper method for building {@link AuthnContextClassRef}.
     * @param value
     * @return
     */
    protected static AuthnContextClassRef buildContextClassRef(final String value) {
        final SAMLObjectBuilder<AuthnContextClassRef> classRefBuilder =
                (SAMLObjectBuilder<AuthnContextClassRef>) XMLObjectProviderRegistrySupport.getBuilderFactory()
                        .<AuthnContextClassRef> getBuilderOrThrow(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        final AuthnContextClassRef classRef = classRefBuilder.buildObject();
        classRef.setAuthnContextClassRef(value);
        return classRef;
    }

    /**
     * Helper method for building {@link AuthnContextDeclRef}.
     * @param value
     * @return
     */
    protected static AuthnContextDeclRef buildContextDeclRef(final String value) {
        final SAMLObjectBuilder<AuthnContextDeclRef> declRefBuilder =
                (SAMLObjectBuilder<AuthnContextDeclRef>) XMLObjectProviderRegistrySupport.getBuilderFactory()
                        .<AuthnContextDeclRef> getBuilderOrThrow(AuthnContextDeclRef.DEFAULT_ELEMENT_NAME);
        final AuthnContextDeclRef declRef = declRefBuilder.buildObject();
        declRef.setAuthnContextDeclRef(value);
        return declRef;
    }
}
