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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.security.auth.Subject;

import net.shibboleth.idp.authn.AbstractValidationAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import fi.mpass.shibboleth.authn.principal.impl.ShibAttributePrincipal;
import fi.mpass.shibboleth.authn.principal.impl.ShibHeaderPrincipal;

/**
 * An action that checks for an {@link ShibbolethSpAuthenticationContext} and produces an
 * {@link net.shibboleth.idp.authn.AuthenticationResult} or records error if the configured user
 * attribute is not existing in the context.
 *  
 * @event {@link EventIds#PROCEED_EVENT_ID}
 * @event {@link EventIds#INVALID_PROFILE_CTX}
 * @event {@link AuthnEventIds#INVALID_AUTHN_CTX}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class).getAttemptedFlow() != null</pre>
 * @post If AuthenticationContext.getSubcontext(ExternalAuthenticationContext.class) != null, then
 * an {@link net.shibboleth.idp.authn.AuthenticationResult} is saved to the {@link AuthenticationContext} on a
 * successful login. On a failed login, the
 * {@link AbstractValidationAction#handleError(ProfileRequestContext, AuthenticationContext, Exception, String)}
 * method is called.
 */
@SuppressWarnings({"unchecked", "rawtypes"})
public class ValidateShibbolethAuthentication extends AbstractValidationAction {

    /** The delimeter if multiple usernameAttributes set. */
    public static final String USERNAME_DELIMITER = ",";

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ValidateShibbolethAuthentication.class);
    
    /** Context containing the result to validate. */
    @Nullable private ShibbolethSpAuthenticationContext shibbolethContext;
    
    /** The attribute name containing the user identifier. */
    @Nonnull @NotEmpty private String usernameAttribute;
    
    /** Switch to populate Subject with attribute principals. */
    private boolean populateAttributes;
    
    /** Switch to populate Subject with header principals. */
    private boolean populateHeaders;
    
    /**
     * Get the attribute name containing the user identifier.
     * @return usernameAttribute.
     */
    public String getUsernameAttribute() {
        return usernameAttribute;
    }
    
    /**
     * Set the attribute name containing the user identifier.
     * @param username The attribute name containing the user identifier.
     */
    public void setUsernameAttribute(String username) {
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);
        Constraint.isNotEmpty(username, "Username attribute cannot be null");
        usernameAttribute = username;
    }
    
    /**
     * Set switch to populate Subject with attribute principals.
     * @param attributes true to populate them, false otherwise.
     */
    public void setPopulateAttributes(boolean attributes) {
        populateAttributes = attributes;
    }
    
    /**
     * Set switch to populate Subject with header principals.
     * @param headers true to populate them, false otherwise.
     */
    
    public void setPopulateHeaders(boolean headers) {
        populateHeaders = headers;
    }
    
    /** {@inheritDoc} */
    @Override
    protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        if (!super.doPreExecute(profileRequestContext, authenticationContext)) {
            return false;
        }
        log.trace("{}: Prerequisities fulfilled to start doPreExecute", getLogPrefix());
        
        shibbolethContext = authenticationContext.getSubcontext(ShibbolethSpAuthenticationContext.class);
        if (shibbolethContext == null) {
            log.debug("{} No ShibbolethAuthenticationContext available within authentication context", 
                    getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_AUTHN_CTX);
            return false;
        }
        
        return true;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        log.trace("{}: Username in attributes={}, headers={}", getLogPrefix(), 
                getUsernameFromMap(shibbolethContext.getAttributes()) != null,
                getUsernameFromMap(shibbolethContext.getHeaders()) != null);            
        if (getUsernameFromMap(shibbolethContext.getAttributes()) == null &&
                getUsernameFromMap(shibbolethContext.getHeaders()) == null) {
            handleError(profileRequestContext, authenticationContext, AuthnEventIds.NO_CREDENTIALS,
                    AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        buildAuthenticationResult(profileRequestContext, authenticationContext);
    }    
    
    /**
     * Returns any username as defined by usernameAttribute from the given map.
     * @param map The map potentially containing usernameAttribute.
     * @return The username.
     */
    protected String getUsernameFromMap(final Map<String, String> map) {
        if (usernameAttribute.contains(USERNAME_DELIMITER)) {
            log.trace("{}: Multiple username attributes configured, browsing through the set", 
                    getLogPrefix());
            final StringTokenizer tokenizer = new StringTokenizer(usernameAttribute, USERNAME_DELIMITER);
            while (tokenizer.hasMoreElements()) {
                final String username = tokenizer.nextToken();
                log.trace("{}: Checking whether {} exists in the map", getLogPrefix(), username);
                if (map.containsKey(username)) {
                    return map.get(username);
                }
            }
        } else {
            log.trace("{}: Single username attribute configured, returning its value from the map", 
                    getLogPrefix());
            return map.get(usernameAttribute);
        } 
        return null;
    }
    
    /** {@inheritDoc} */
    @Override
    @Nonnull protected Subject populateSubject(@Nonnull final Subject subject) {
        if (getUsernameFromMap(shibbolethContext.getAttributes()) != null) {
            subject.getPrincipals().add(
                    new UsernamePrincipal(getUsernameFromMap(shibbolethContext.getAttributes())));
        } else {
            subject.getPrincipals().add(
                    new UsernamePrincipal(getUsernameFromMap(shibbolethContext.getHeaders())));
        }
        if (populateAttributes) {
            log.debug("{} Populating the attribute principals into the subject", getLogPrefix());
            subject.getPrincipals().addAll(populateAttributePrincipals());
        }
        if (populateHeaders) {
            log.debug("{} Populating the headers principals into the subject", getLogPrefix());
            subject.getPrincipals().addAll(populateHeaderPrincipals());
        }
        return subject;
    }
    
    /**
     * Populates all request attributes to a set of {@link ShibAttributePrincipal}s.
     * @return The set containing all request attributes.
     */
    protected Set<Principal> populateAttributePrincipals() {
        return populatePrincipals(shibbolethContext.getAttributes(), false);
    }
    
    /** Populates all HTTP headers to a set of {@link ShibHeaderPrincipal}s.
     * @return The set containing all HTTP headers.
     */
    protected Set<Principal> populateHeaderPrincipals() {
        return populatePrincipals(shibbolethContext.getHeaders(), true);
    }
    
    /**
     * Populate all map entries to a set of {@link KeyValuePrincipal}s.
     * @param map The map containing entries to be populated.
     * @param isHeader If true, {@link ShibHeaderPrincipal} is used, {@link ShibAttributePrincipal} otherwise.
     * @return The set containing all the entries from the given map.
     */
    protected Set<Principal> populatePrincipals(Map<String, String> map, boolean isHeader) {
        final Set<Principal> set = new HashSet<Principal>();
        final Iterator<String> iterator = map.keySet().iterator();
        while (iterator.hasNext()) {
            final String key = iterator.next();
            if (isHeader) {
                log.trace("Adding HTTP request principal {} to the set", key);
                set.add(new ShibHeaderPrincipal(key, map.get(key)));
            } else {
                log.trace("Adding attribute principal {} to the set", key);
                set.add(new ShibAttributePrincipal(key, map.get(key)));
            }
        }
        return set;
    }
}
