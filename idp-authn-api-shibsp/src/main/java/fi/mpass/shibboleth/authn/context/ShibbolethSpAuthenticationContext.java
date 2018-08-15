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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nonnull;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;

import org.opensaml.messaging.context.BaseContext;

/**
 * This context stores attributes coming from Shibboleth SP.
 */
public class ShibbolethSpAuthenticationContext extends BaseContext {

    /** Shibboleth SP session index attribute name. */
    public static final String SHIB_SP_SESSION_INDEX = "Shib-Session-Index";

    /** Shibboleth SP application id attribute name. */
    public static final String SHIB_SP_APPLICATION_ID = "Shib-Application-ID";

    /** Shibboleth SP session id attribute name. */
    public static final String SHIB_SP_SESSION_ID = "Shib-Session-ID";

    /** Shibboleth SP authentication instant attribute name. */
    public static final String SHIB_SP_AUTHENTICATION_INSTANT = "Shib-Authentication-Instant";

    /** Shibboleth SP authentication method attribute name. */
    public static final String SHIB_SP_AUTHENTICATION_METHOD = "Shib-Authentication-Method";

    /** Shibboleth SP identity provider attribute name. */
    public static final String SHIB_SP_IDENTITY_PROVIDER = "Shib-Identity-Provider";

    /** Shibboleth SP authentication context class attribute name. */
    public static final String SHIB_SP_AUTHN_CONTEXT_CLASS = "Shib-AuthnContext-Class";
    
    /** Shibboleth SP authentication context declaration attribute name. */
    public static final String SHIB_SP_AUTHN_CONTEXT_DECL = "Shib-AuthnContext-Decl";

    /** Map of http headers values. */
    @Nonnull @NotEmpty private Map<String, String> headers;
    
    /** Map of request attribute values. */
    @Nonnull @NotEmpty private Map<String, String> attributes;
    
    /** The IdP who authenticated the user. */
    @Nonnull @NotEmpty private String idp;

    /** The authentication instant when user was authenticated at the IdP. */
    @Nonnull @NotEmpty private String instant;

    /** The authentication method how user was authenticated at the IdP. */
    @Nonnull @NotEmpty private String method;

    /** The authentication context class how user was authenticated at the IdP. */
    @Nonnull @NotEmpty private String contextClass;

    /** The authentication context declaration how user was authenticated at the IdP. */
    private String contextDecl;
    
    /** The initial authentication context requested from this IdP. */
    private List<Principal> initialRequestedContext;
    
    /** The mapped authentication context to be requested from the authenticating IdP. */
    private List<Principal> mappedAuthnContext;

    /**
     * Constructor.
     */
    public ShibbolethSpAuthenticationContext() {
        headers = new HashMap<String, String>();
        attributes = new HashMap<String, String>();
    }
    
    /**
     * Get the Http headers.
     * 
     * @return headers
     */
    @Nonnull @NotEmpty public Map<String, String> getHeaders() {
        return headers;
    }
    
    /**
     * Set the Http headers.
     * 
     * @param httpHeaders The Http headers.
     */
    @Nonnull @NotEmpty public void setHeaders(Map<String, String> httpHeaders) {
        headers = httpHeaders;
    }

    /**
     * Get the request attributes.
     * 
     * @return attributes
     */
    @Nonnull @NotEmpty public Map<String, String> getAttributes() {
        return attributes;
    }
    
    /**
     * Set the request attributes.
     * 
     * @param requestAttributes The request attributes.
     */
    @Nonnull @NotEmpty public void setAttributes(Map<String, String> requestAttributes) {
        attributes = requestAttributes;
    }

    /**
     * Get the IdP who authenticated the user.
     * 
     * @return idp
     */
    @Nonnull @NotEmpty public String getIdp() {
        return idp;
    }

    /**
     * Set the IdP who authenticated the user.
     * 
     * @param identityProvider What to set.
     * @return idp
     */
    @Nonnull @NotEmpty public String setIdp(@Nonnull @NotEmpty final String identityProvider) {
        idp = identityProvider;
        return idp;
    }

    /**
     * Get the authentication instant when user was authenticated at the IdP.
     * 
     * @return instant
     */
    @Nonnull @NotEmpty public String getInstant() {
        return instant;
    }

    /**
     * Set the authentication instant when user was authenticated at the IdP.
     * 
     * @param authnInstant What to set.
     * @return authnInstant
     */
    @Nonnull @NotEmpty public String setInstant(@Nonnull @NotEmpty final String authnInstant) {
        instant = authnInstant;
        return instant;
    }

    /**
     * Get the authentication method how user was authenticated at the IdP.
     * 
     * @return method
     */
    @Nonnull @NotEmpty public String getMethod() {
        return method;
    }

    /**
     * Set the authentication method how user was authenticated at the IdP.
     * 
     * @param authnMethod What to set.
     * @return method
     */
    @Nonnull @NotEmpty public String setMethod(@Nonnull @NotEmpty final String authnMethod) {
        method = authnMethod;
        return method;
    }

    /**
     * Get the authentication context class how user was authenticated at the IdP.
     * 
     * @return contextClass
     */
    @Nonnull @NotEmpty public String getContextClass() {
        return contextClass;
    }

    /**
     * Set the authentication context class how user was authenticated at the IdP.
     * 
     * @param authnContextClass What to set.
     * @return contextClass
     */
    @Nonnull @NotEmpty public String setContextClass(@Nonnull @NotEmpty final String authnContextClass) {
        contextClass = authnContextClass;
        return contextClass;
    }

    /**
     * Get the authentication context declaration how user was authenticated at the IdP.
     * 
     * @return contextDecl
     */
    @Nonnull @NotEmpty public String getContextDecl() {
        return contextDecl;
    }

    /**
     * Set the authentication context declaration how user was authenticated at the IdP.
     * 
     * @param authnContextDecl What to set.
     * @return contextClass
     */
    @Nonnull @NotEmpty public String setContextDecl(@Nonnull @NotEmpty final String authnContextDecl) {
        contextDecl = authnContextDecl;
        return contextDecl;
    }

    /**
     * Get the initial authentication context requested from this IdP.
     * 
     * @return initialRequestedContext
     */
    public List<Principal> getInitialRequestedContext() {
        return initialRequestedContext;
    }
    
    /**
     * Get the initial authentication context requested from this IdP.
     * 
     * @param initialContext What to set.
     * @return initialRequestedContext
     */
    public List<Principal> setInitialRequestedContext(final List<Principal> initialContext) {
        initialRequestedContext = initialContext;
        return initialRequestedContext;
    }

    /**
     * Get the mapped authentication context to be requested from the authenticating IdP.
     * 
     * @return mappedAuthnContext
     */
    public List<Principal> getMappedAuthnContext() {
        return mappedAuthnContext;
    }
    
    /**
     * Get the mapped authentication context to be requested from the authenticating IdP.
     * 
     * @param mappedContext What to set.
     * @return mappedAuthnContext
     */
    public List<Principal> setMappedAuthnContext(final List<Principal> mappedContext) {
        mappedAuthnContext = mappedContext;
        return mappedAuthnContext;
    }

}