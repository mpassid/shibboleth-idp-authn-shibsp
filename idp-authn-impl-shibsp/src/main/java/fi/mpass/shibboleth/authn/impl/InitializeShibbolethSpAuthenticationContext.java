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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.messaging.context.navigate.MessageLookup;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.context.navigate.InboundMessageContextLookup;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextDeclRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;

import fi.mpass.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.profile.ActionSupport;
import net.shibboleth.idp.profile.IdPEventIds;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.saml.authn.principal.AuthnContextClassRefPrincipal;
import net.shibboleth.idp.saml.authn.principal.AuthnContextDeclRefPrincipal;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * An action that creates an {@link ShibbolethSpAuthenticationContext} and attaches it to {@link AuthenticationContext}.
 * If configured for the relying party, the requested authentication context is mapped according to the configuration.
 * 
 * @event {@link EventIds#INVALID_PROFILE_CTX}
 * @event {@link IdPEventIds#INVALID_RELYING_PARTY_CTX}
 */
@SuppressWarnings("rawtypes")
public class InitializeShibbolethSpAuthenticationContext extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull
    private final Logger log = LoggerFactory.getLogger(InitializeShibbolethSpAuthenticationContext.class);

    /**
     * Strategy used to locate the {@link RelyingPartyContext} associated with a given {@link ProfileRequestContext}.
     */
    @Nonnull
    private Function<ProfileRequestContext, RelyingPartyContext> relyingPartyContextLookupStrategy;

    /** Lookup strategy function for obtaining {@link AuthnRequest}. */
    @Nonnull
    private Function<ProfileRequestContext, AuthnRequest> authnRequestLookupStrategy;

    /** The request message to read from. */
    @Nullable
    private AuthnRequest authnRequest;

    /**
     * The mappings of the authentication context classes between the initial request and the request to the
     * authenticating Identity Provider.
     */
    @Nullable
    private Map<String, Map<Principal, Principal>> authnContextMappings;

    /**
     * The relying party specific mappings.
     */
    private Map<Principal, Principal> rpMappings;

    /** Constructor. */
    public InitializeShibbolethSpAuthenticationContext() {
        authnRequestLookupStrategy =
                Functions.compose(new MessageLookup<>(AuthnRequest.class), new InboundMessageContextLookup());
        relyingPartyContextLookupStrategy = new ChildContextLookup<>(RelyingPartyContext.class);
    }

    /**
     * Set the strategy used to locate the {@link RelyingPartyContext} associated with a given
     * {@link ProfileRequestContext}.
     * 
     * @param strategy strategy used to locate the {@link RelyingPartyContext} associated with a given
     *            {@link ProfileRequestContext}
     */
    public void setRelyingPartyContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, RelyingPartyContext> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        relyingPartyContextLookupStrategy =
                Constraint.isNotNull(strategy, "RelyingPartyContext lookup strategy cannot be null");
    }

    /**
     * Set the strategy used to locate the {@link AuthnRequest} to read from.
     * 
     * @param strategy lookup strategy
     */
    public void setAuthnRequestLookupStrategy(@Nonnull final Function<ProfileRequestContext, AuthnRequest> strategy) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        authnRequestLookupStrategy = Constraint.isNotNull(strategy, "AuthnRequest lookup strategy cannot be null");
    }

    /**
     * Set the context mappings.
     * 
     * @param mappings The key refers to the relying party ID (entityID).
     */
    public void setAuthnContextMappings(@Nonnull final Map<String, Map<Principal, Principal>> mappings) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        authnContextMappings = mappings;
    }

    /** {@inheritDoc} */
    @SuppressWarnings("unchecked")
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            log.trace("{} The super class method returned false, nothing to do.", getLogPrefix());
            return false;
        }

        final RelyingPartyContext rpCtx = relyingPartyContextLookupStrategy.apply(profileRequestContext);
        if (rpCtx == null || StringSupport.trimOrNull(rpCtx.getRelyingPartyId()) == null) {
            log.debug("{} No relying party context or relying party entity ID", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, IdPEventIds.INVALID_RELYING_PARTY_CTX);
            return false;
        }
        if (authnContextMappings != null) {
            rpMappings = authnContextMappings.get(rpCtx.getRelyingPartyId());
            log.debug("{} Relying party specific mappings for {}: {}", getLogPrefix(), rpCtx.getRelyingPartyId(),
                    authnContextMappings.containsKey(rpCtx.getRelyingPartyId()));
        } else {
            log.debug("{} No authn context mappings defined", getLogPrefix());
        }

        authnRequest = authnRequestLookupStrategy.apply(profileRequestContext);
        if (authnRequest == null) {
            log.error("{} AuthnRequest message was not returned by lookup strategy", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, EventIds.INVALID_PROFILE_CTX);
            return false;
        }
        return true;
    }

    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        final ShibbolethSpAuthenticationContext shibSpContext =
                authenticationContext.getSubcontext(ShibbolethSpAuthenticationContext.class, true);

        final List<Principal> initialRequestedContext = new ArrayList<>();
        final List<Principal> mappedAuthnContext = new ArrayList<>();

        final RequestedAuthnContext requestedContext = authnRequest.getRequestedAuthnContext();
        if (requestedContext == null) {
            log.debug("{} No requested authentication context in the request.", getLogPrefix());
            if (rpMappings != null && rpMappings.containsKey(null)) {
                log.debug("{} Empty requested context mapped to {}", getLogPrefix(), rpMappings.get(null));
                mappedAuthnContext.add(rpMappings.get(null));
            }
        } else {
            mapAuthnContextClassRefs(requestedContext.getAuthnContextClassRefs(), initialRequestedContext,
                    mappedAuthnContext);
            mapAuthnContextDeclRefs(requestedContext.getAuthnContextDeclRefs(), initialRequestedContext,
                    mappedAuthnContext);
        }

        shibSpContext.setInitialRequestedContext(initialRequestedContext);
        shibSpContext.setMappedAuthnContext(mappedAuthnContext);
    }

    /**
     * Maps the authentication context class references and stored them to the given lists.
     * 
     * @param contextClassRefs The list of {@link AuthnContextClassRef}s.
     * @param initialRequestedContext The list of initial {@link Principal}s.
     * @param mappedAuthnContext The list of mapped {@link Principal}s.
     */
    protected void mapAuthnContextClassRefs(final List<AuthnContextClassRef> contextClassRefs,
            final List<Principal> initialRequestedContext, final List<Principal> mappedAuthnContext) {
        for (final AuthnContextClassRef classRef : contextClassRefs) {
            final String ctxClassRef = classRef.getAuthnContextClassRef();
            final AuthnContextClassRefPrincipal principal = new AuthnContextClassRefPrincipal(ctxClassRef);
            mapPrincipal(principal, initialRequestedContext, mappedAuthnContext);
        }

    }

    /**
     * Maps the authentication context declaration references and stores them to the given lists.
     * 
     * @param contextDeclRefs The list of {@link AuthnContextDeclRef}s.
     * @param initialRequestedContext The list of initial {@link Principal}s.
     * @param mappedAuthnContext The list of mapped {@link Principal}s.
     */
    protected void mapAuthnContextDeclRefs(final List<AuthnContextDeclRef> contextDeclRefs,
            final List<Principal> initialRequestedContext, final List<Principal> mappedAuthnContext) {
        for (final AuthnContextDeclRef declRef : contextDeclRefs) {
            final String ctxDeclRef = declRef.getAuthnContextDeclRef();
            final AuthnContextDeclRefPrincipal principal = new AuthnContextDeclRefPrincipal(ctxDeclRef);
            mapPrincipal(principal, initialRequestedContext, mappedAuthnContext);
        }
    }

    /**
     * Maps a principal and stores it to the given lists.
     * 
     * @param principal The {@link Principal} to be mapped.
     * @param initialRequestedContext The initial {@link Principal} is stored here.
     * @param mappedAuthnContext The mapped {@link Principal} is stored here.
     */
    protected void mapPrincipal(final Principal principal, final List<Principal> initialRequestedContext,
            final List<Principal> mappedAuthnContext) {
        initialRequestedContext.add(principal);
        log.debug("{} Initial request contained authentication context reference: {}", getLogPrefix(),
                principal.getClass().getName());
        if (rpMappings != null && rpMappings.containsKey(principal)) {
            log.debug("{} Initial requested context mapped to {}", getLogPrefix(), rpMappings.get(principal));
            mappedAuthnContext.add(rpMappings.get(principal));
        } else {
            log.debug("{} Initial requested context preserved without mapping", getLogPrefix());
            mappedAuthnContext.add(principal);
        }
    }
}
