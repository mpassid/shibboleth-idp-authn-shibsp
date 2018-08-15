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

import java.io.IOException;
import java.util.Enumeration;

import javax.annotation.Nonnull;
import javax.security.auth.Subject;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import net.shibboleth.idp.authn.ExternalAuthentication;
import net.shibboleth.idp.authn.ExternalAuthenticationException;
import net.shibboleth.idp.authn.principal.UsernamePrincipal;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import fi.mpass.shibboleth.authn.principal.impl.ShibHeaderPrincipal;

/**
 * This class parses REMOTE_USER and Shibboleth headers from the {@link HttpServletRequest}. The REMOTE_USER is put
 * inside the {@link UsernamePrincipal} while all Http headers are stored inside {@link ShibHeaderPrincipal}. All the
 * principals are stored inside {@link Subject} which is communicated back to the Shibboleth IdP as request attribute.
 */
@SuppressWarnings("serial")
@WebServlet(name = "ShibbolethSpAuthnServlet")
public class ShibbolethSpAuthnServlet extends HttpServlet {

    /** The header name for the REMOTE_USER. */
    public static final String HEADER_NAME_REMOTE_USER = "REMOTE_USER";
    
    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(ShibbolethSpAuthnServlet.class);

    /** {@inheritDoc} */
    public void init(final ServletConfig config) throws ServletException {
        log.trace("Initializing the servlet");
    }

    /** {@inheritDoc} */
    public void doGet(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        log.trace("Processing a request");
        try {
            final String id = ExternalAuthentication.startExternalAuthentication(request);
            final Subject subject = new Subject();
            log.trace("REMOTE_USER header {}", request.getHeader(HEADER_NAME_REMOTE_USER));
            String username = request.getHeader(HEADER_NAME_REMOTE_USER);
            log.trace("Servlet remote user {}", request.getRemoteUser());
            if (StringSupport.trimOrNull(username) == null) {
                username = request.getRemoteUser();
            }
            if (StringSupport.trimOrNull(username) != null) {
                subject.getPrincipals().add(new UsernamePrincipal(username));
                log.debug("User identity extracted from REMOTE_USER: {}", username);
            } else {
                log.debug("No remote user provided");
            }

            final Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                final String header = headerNames.nextElement();
                final String value = request.getHeader(header);
                log.trace("Header name {} has value {}", header, value);
                if (value != null && !value.isEmpty()) {
                    subject.getPrincipals().add(new ShibHeaderPrincipal(header, value));
                    log.debug("Header {} added to the set of Principals", header);
                }
            }
            // attributes are currently only logged for trace level
            if (log.isTraceEnabled()) {
                final Enumeration<String> attributeNames = request.getAttributeNames();
                while (attributeNames.hasMoreElements()) {
                    final String attribute = attributeNames.nextElement();
                    log.trace("Attribute name {} has value {}", attribute, request.getAttribute(attribute));
                }
            }
            request.setAttribute(ExternalAuthentication.SUBJECT_KEY, subject);
            log.debug("Subject populated and added to the request");
            ExternalAuthentication.finishExternalAuthentication(id, request, response);
        } catch (final ExternalAuthenticationException e) {
            log.warn("External authentication exception", e);
        }
    }
}