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

import java.io.UnsupportedEncodingException;
import java.util.Enumeration;
import java.util.List;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AbstractExtractionAction;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.ExternalAuthenticationContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.context.ShibbolethSpAuthenticationContext;
import fi.mpass.shibboleth.authn.principal.impl.ShibHeaderPrincipal;

/**
 * An action that extracts a Http headers and request attributes, creates and populates a 
 * {@link ShibbolethSpAuthenticationContext}, and attaches it to the {@link AuthenticationContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 * @post If getHttpServletRequest() != null, HTTP headers and request attributes with String values are
 * extracted to populate a {@link ShibbolethSpAuthenticationContext}. */
@SuppressWarnings("rawtypes")
public class ExtractShibbolethAttributesFromRequest extends AbstractExtractionAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ExtractShibbolethAttributesFromRequest.class);
    
    /** The possible prefix for the Shibboleth attribute names. */
    private final String variablePrefix;
    
    /** Whether exploit the external authentication context. */
    private boolean exploitExternal;
    
    /** The encoding for headers. If not set to null, the header values are transformed into UTF-8. */
    private String headerEncoding;
    
    /** The list of request attribute names (Apache environment variable names) to be fetched. */
    private List<String> attributeNames;

    /**
     * Constructor.
     */
    public ExtractShibbolethAttributesFromRequest() {
        this("");
    }
    
    /**
     * Constructor.
     * 
     * @param prefix The possible prefix for the Shibboleth header/attribute names.
     */
    public ExtractShibbolethAttributesFromRequest(String prefix) {
        super();
        variablePrefix = prefix;
        setExploitExternal(false);
        setHeaderEncoding(null);
        setAttributeNames(null);
    }

    /**
     * Set whether exploit the external authentication context.
     * @param check What to set.
     */
    public void setExploitExternal(final boolean check) {
        exploitExternal = check;
    }
    
    /**
     * Whether exploit the external authentication context.
     * @return Whether exploit the external authentication context.
     */
    public boolean isExploitExternal() {
        return exploitExternal;
    }
    
    /**
     * Set the encoding for headers. If not set to null, the header values are transformed into UTF-8.
     * @param encoding What to set.
     */
    public void setHeaderEncoding(final String encoding) {
        headerEncoding = encoding;
    }
    
    /**
     * Set the list of request attribute names (Apache environment variable names) to be fetched.
     * @param names What to set.
     */
    public void setAttributeNames(final List<String> names) {
        attributeNames = names;
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();
        if (attributeNames == null) {
            log.warn("{} attributeNames property is set to null: no attributes " 
                    + "(Apache environment variables) can be resolved", getLogPrefix());
        }
    }
    
    /** {@inheritDoc} */
    @Override
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {
        
        final HttpServletRequest request = getHttpServletRequest();
        if (request == null) {
            log.debug("{} Profile action does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        
        if (log.isTraceEnabled()) {
            logHeadersAndAttributes(request);
        }
        final ShibbolethSpAuthenticationContext shibbolethContext =
                authenticationContext.getSubcontext(ShibbolethSpAuthenticationContext.class, true);
        if (isExploitExternal()) {
            log.debug("{} Exploiting External Authentication", getLogPrefix());
            final ExternalAuthenticationContext extContext =
                    authenticationContext.getSubcontext(ExternalAuthenticationContext.class);
            if (extContext == null) {
                log.error("{} External Authentication context not found!", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                return;
            }
            final Subject subject = extContext.getSubject();
            if (subject == null) {
                log.error("{} No subject in the External Authentication context!", getLogPrefix());
                ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
                return;
            }
            for (final ShibHeaderPrincipal principal : subject.getPrincipals(ShibHeaderPrincipal.class)) {
                final String header = principal.getKey();
                final String value = principal.getValue();
                updateShibbolethContext(shibbolethContext, header, value, true);
            }
        } else {
            log.debug("{} Checking headers and attributes, not External Authentication", getLogPrefix());
            final Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                final String header = headerNames.nextElement();
                final String value = StringSupport.trimOrNull(request.getHeader(header));
                updateShibbolethContext(shibbolethContext, header, value, true);
            }
            if (attributeNames != null) {
                for (final String name : attributeNames) {
                    if (request.getAttribute(name) instanceof String) {
                        final String value = StringSupport.trimOrNull((String)request.getAttribute(name));
                        updateShibbolethContext(shibbolethContext, name, value, false);
                    } else {
                        log.debug("{} Ignoring request attribute {}", getLogPrefix(), name);
                    }
                }
            }
        }
    }
    
    /**
     * Updates the given {@link ShibbolethContext} with given parameters.
     * @param shibbolethContext The Shibboleth context.
     * @param name The name of the variable to be updated.
     * @param value The value of the variable to be updated.
     * @param isHeader Is the variable HTTP header (if false, it's request attribute).
     */
    protected void updateShibbolethContext(final ShibbolethSpAuthenticationContext shibbolethContext, 
            final String name, final String value, final boolean isHeader) {
        if (value == null) {
            log.trace("{} The value is null, {} will be ignored", getLogPrefix(), name);
            return;
        }
        final String key = stripPrefixIfExists(name);
        if (key.equals(ShibbolethSpAuthenticationContext.SHIB_SP_IDENTITY_PROVIDER)) {
            log.debug("{} Added value for Identity Provider", getLogPrefix());
            shibbolethContext.setIdp(applyTransforms(value));            
        } else if (key.equals(ShibbolethSpAuthenticationContext.SHIB_SP_AUTHENTICATION_INSTANT)) {
            log.debug("{} Added value for Authentication Instant", getLogPrefix());
            shibbolethContext.setInstant(applyTransforms(value));
        } else if (key.equals(ShibbolethSpAuthenticationContext.SHIB_SP_AUTHENTICATION_METHOD)) {
            log.debug("{} Added value for Authentication Method", getLogPrefix());
            shibbolethContext.setMethod(applyTransforms(value));
        } else if (key.equals(ShibbolethSpAuthenticationContext.SHIB_SP_AUTHN_CONTEXT_CLASS)) {
            log.debug("{} Added value for Authentication Context Class", getLogPrefix());
            shibbolethContext.setContextClass(applyTransforms(value));
        } else if (key.equals(ShibbolethSpAuthenticationContext.SHIB_SP_AUTHN_CONTEXT_DECL)) {
            log.debug("{} Added value for Authentication Context Decl", getLogPrefix());
            shibbolethContext.setContextDecl(applyTransforms(value));
        }
       
        if (isHeader) {
            if (headerEncoding == null) {
                shibbolethContext.getHeaders().put(key, applyTransforms(value));
                log.debug("{} Added value for header {}", getLogPrefix(), key);
            } else {
                try {
                    byte[] bytes = value.getBytes(headerEncoding);
                    final String newValue = new String(bytes, "UTF-8");
                    shibbolethContext.getHeaders().put(key, applyTransforms(newValue));
                    log.debug("{} Transformed a value for header {}", getLogPrefix(), key);
                } catch (UnsupportedEncodingException e) {
                    log.warn("{} Could not transform a header value", getLogPrefix(), e);
                }
            }
        } else {
            log.debug("{} Added value for attribute {}", getLogPrefix(), key);
            shibbolethContext.getAttributes().put(key, applyTransforms(value));
        }
    }
    
    /**
     * Strips the variablePrefix from the given String if exists.
     * @param name The String to be checked.
     * @return name without variablePrefix, if it existed.
     */
    protected String stripPrefixIfExists(@Nonnull final String name) {
        if (name.startsWith(variablePrefix)) {
            return name.substring(variablePrefix.length());
        }
        return name;
    }

    /**
     * Iterates over HTTP headers and attributes and logs their value in TRACE-level.
     * @param request The servlet request.
     */
    protected void logHeadersAndAttributes(HttpServletRequest request) {
        final Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            final String header = headerNames.nextElement();
            final String value = request.getHeader(header);
            
            log.trace("Header name {} has a raw value {}", header, value);
            if (headerEncoding != null) {
                try {
                    byte[] bytes = value.getBytes(headerEncoding);
                    final String newValue = new String(bytes, "UTF-8");
                    log.trace("Header name {} has a transformed value {}", header, newValue);
                } catch (UnsupportedEncodingException e) {
                    log.warn("{} Could not transform a header value", getLogPrefix(), e);
                }
                
            }
        }
        if (attributeNames == null) {
            log.warn("{} No attributeNames defined, cannot parse the values", getLogPrefix());
        } else {
            for (String attribute : attributeNames) {
                log.trace("Attribute name {} has value {}", attribute, request.getAttribute(attribute));
            }
        }
    }
}
