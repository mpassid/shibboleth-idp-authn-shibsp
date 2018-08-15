# Shibboleth IdP v3: Shibboleth SP authentication

## Overview

This module implements an authentication flow for [Shibboleth Identity Provider v3](https://wiki.shibboleth.net/confluence/display/IDP30/Home) exploiting attributes provided by [Shibboleth Service Provider](https://shibboleth.net/products/service-provider.html). The module can be used for outsourcing the authentication to another SAML IdP instead of prompting and validating the user
credentials itself.

## Prerequisities and compilation

- Java 7+
- [Apache Maven 3](https://maven.apache.org/)

```
mvn package
```

After successful compilation, the _target_ directory contains _shibboleth-idp-authn-shibsp-\<version\>.zip_
archive.

## Deployment

After compilation, the module's JAR-files must be deployed to the IdP Web
application. Also, the module's authentication flow and its bean definitions must
be deployed to the IdP. Depending on the IdP installation, the module deployment may be achieved for instance 
with the following sequence:

```
unzip target/shibboleth-idp-authn-shibsp-<version>.zip
cp shibboleth-idp-authn-shibsp-<version>/edit-webapp/WEB-INF/lib/* /opt/shibboleth-idp/edit-webapp/WEB-INF/lib
cp -r shibboleth-idp-authn-shibsp-<version>/flows/* /opt/shibboleth-idp/flows
cp shibboleth-idp-authn-shibsp-<version>/conf/* /opt/shibboleth-idp/conf/authn
cd /opt/shibboleth-idp
sh bin/build.sh
```

The final command will rebuild the _war_-package for the IdP application.

## Configuration

The distribution package contains three different authentication flows: _authn/Shib_, _authn/ShibExample_ and _authn/ShibExternal_. The first
one is an abstract flow that contains general steps exploited by the other two flows. Typically, the deployer doesn't need to customize the
abstract flow or its beans.

### authn/ShibExample

This flow assumes that the URL location where the end-user is accessing the IDP is protected by Shibboleth SP. In other words, the
Shibboleth SP must be configured to provide the Apache environment and/or HTTP headers to the location. Typically the URL location
corresponds to the endpoint where Shibboleth IdP receives the incoming authentication request, for instance 
*https://idp.example.org/idp/profile/SAML2/Redirect/SSO*.

```
<flow xmlns="http://www.springframework.org/schema/webflow"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://www.springframework.org/schema/webflow http://www.springframework.org/schema/webflow/spring-webflow.xsd"
      parent="authn/Shib">

    <view-state id="ExternalTransfer" view="externalRedirect:#{flowRequestContext.getActiveFlow().getApplicationContext().getBean('shibboleth.authn.ShibExample.externalAuthnPath')}&amp;forceAuthn=#{opensamlProfileRequestContext.getSubcontext(T(net.shibboleth.idp.authn.context.AuthenticationContext)).isForceAuthn()}&amp;isPassive=#{opensamlProfileRequestContext.getSubcontext(T(net.shibboleth.idp.authn.context.AuthenticationContext)).isPassive()}&amp;target=#{flowExecutionUrl}%26_eventId_proceed%3D1">
        <transition to="ValidateShibFlowAuthentication" />
    </view-state>
    
</flow>
```

The example above assumes that you have a bean called _shibboleth.authn.ShibExample.externalAuthnPath_ configured in the file 
_/opt/shibboleth-idp/conf/authn/shib-authn-config.xml_. The bean must contain the desired
[Shibboleth SP Handler](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPHandler) location and its parameters.

### authn/ShibExternal

In comparison to the previous flow, this flow is more flexible regarding the Shibboleth SP configuration. On the other hand, the
configuration requires some extra steps, explained below.

```
<flow xmlns="http://www.springframework.org/schema/webflow"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="http://www.springframework.org/schema/webflow http://www.springframework.org/schema/webflow/spring-webflow.xsd"
      parent="authn/Shib">

    <view-state id="ExternalTransfer" view="externalRedirect:#{flowRequestContext.getActiveFlow().getApplicationContext().getBean('shibboleth.authn.ShibExternal.externalHandler')}&amp;forceAuthn=#{opensamlProfileRequestContext.getSubcontext(T(net.shibboleth.idp.authn.context.AuthenticationContext)).isForceAuthn()}&amp;isPassive=#{opensamlProfileRequestContext.getSubcontext(T(net.shibboleth.idp.authn.context.AuthenticationContext)).isPassive()}&amp;target=#{flowRequestContext.getActiveFlow().getApplicationContext().getBean('shibboleth.authn.ShibExternal.externalAuthServlet')}%3Fconversation=#{flowExecutionContext.getKey().toString()}">
        <on-render>
            <evaluate expression="opensamlProfileRequestContext.getSubcontext(T(net.shibboleth.idp.authn.context.AuthenticationContext)).getSubcontext(T(net.shibboleth.idp.authn.context.ExternalAuthenticationContext), true).setFlowExecutionUrl(flowExecutionUrl + '&amp;_eventId_proceed=1')" />
            <evaluate expression="externalContext.getNativeRequest().getSession().setAttribute('conversation' + flowExecutionContext.getKey().toString(), new net.shibboleth.idp.authn.impl.ExternalAuthenticationImpl(opensamlProfileRequestContext))" />
        </on-render>
        <transition to="ValidateShibExternalAuthentication" />
    </view-state>
    
</flow>
```

The example above assumes that you have a bean called _shibboleth.authn.ShibExternal.externalAuthnPath_ configured in the file 
_/opt/shibboleth-idp/conf/authn/shib-authn-config.xml_. The bean must contain the desired
[Shibboleth SP Handler](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPHandler) location and its parameters. Also, a bean
called _shibboleth.authn.ShibExternal.externalAuthServlet_ must be configured in the same file, and it must correspond to the location
of the _fi.mpass.shibboleth.authn.impl.ShibbolethSpAuthnServlet_ servlet.

```
...
    <bean id="shibboleth.authn.ShibExternal.externalHandler" class="java.lang.String"
        c:_0="https://idp.example.org/override/Shibboleth.sso/Login?entityID=https://idp2.example.org/idp/shibboleth" />

    <bean id="shibboleth.authn.ShibExternal.externalAuthServlet" class="java.lang.String"
        c:_0="https://idp.example.org/idp/Authn/ShibExternal" />
...
```


The servlet is configured in the *web.xml* (usually _/opt/shibboleth-idp/edit-webapp/WEB-INF/web.xml_).

```
...
    <servlet>
        <servlet-name>ShibbolethSpAuthnServlet</servlet-name>
        <servlet-class>fi.mpass.shibboleth.authn.impl.ShibbolethSpAuthnServlet</servlet-class>
        <load-on-startup>2</load-on-startup>
    </servlet>
    <servlet-mapping>
        <servlet-name>ShibbolethSpAuthnServlet</servlet-name>
        <url-pattern>/Authn/ShibExternal</url-pattern>
    </servlet-mapping>
...
```


It should be noted that with the _authn/ShibExternal_ flow, it is possible to configure multiple flows with different SP Handler 
configurations, by using [ApplicationOverride](https://wiki.shibboleth.net/confluence/display/SHIB2/NativeSPApplicationOverride).

Finally, you will need to add the new authentication flow definition(s) to _/opt/shibboleth-idp/conf/authn/general-authn.xml_:

```
<bean id="authn/ShibExample" parent="shibboleth.AuthenticationFlow"
            p:nonBrowserSupported="false" p:forcedAuthenticationSupported="true"/>
```

The flow definition must also be enabled via _idp.authn.flows_ variable in _/opt/shibboleth-idp/conf/idp.properties_.

## Attribute resolution

The attributes provided by Shibboleth SP can be converted into IdP attributes in the following way:

### 1. Enable attribute and/or header population into Subject

In the _/opt/shibboleth-idp/flows/authn/Shib/shib-beans.xml_, enable _populateAttributes_ and/or _populateHeaders_ settings for the bean _ValidateShibbolethAuthentication_.

The example above enables population of both attributes and headers:

```
   <bean id="ValidateShibbolethAuthentication"
            class="fi.mpass.shibboleth.authn.impl.ValidateShibbolethAuthentication" scope="prototype"
            p:classifiedMessages-ref="shibboleth.authn.Shib.ClassifiedMessageMap"
            p:resultCachingPredicate="#{getObject('shibboleth.authn.Shib.resultCachingPredicate')}"
            p:usernameAttribute="eppn" p:populateHeaders="true" p:populateAttributes="true" />
```

### 2. Enable principal serializers

In order to serialize the Shibboleth attributes and/or headers, the following serializers need to be added into _shibboleth.PrincipalSerializers_ list in _opt/shibboleth-idp/conf/global.xml_: 

* _fi.mpass.shibboleth.authn.principal.impl.ShibAttributePrincipalSerializer_ for attributes
* _fi.mpass.shibboleth.authn.principal.impl.ShibHeaderPrincipalSerializer_ for headers

The example below enables serialization of both attributes and headers. The other serializers are the same ones that are defined in the _/opt/shibboleth-idp/system/conf/general-authn-system.xml_ (see bean _shibboleth.DefaultPrincipalSerializers_).

```
<bean id="shibboleth.PrincipalSerializers"
        class="org.springframework.beans.factory.config.ListFactoryBean">
    <property name="sourceList">
        <list>
            <bean class="fi.mpass.shibboleth.authn.principal.impl.ShibAttributePrincipalSerializer" />
            <bean class="fi.mpass.shibboleth.authn.principal.impl.ShibHeaderPrincipalSerializer" />
            <bean class="net.shibboleth.idp.authn.principal.impl.UsernamePrincipalSerializer" />
            <bean class="net.shibboleth.idp.authn.principal.impl.LDAPPrincipalSerializer" />
            <bean class="net.shibboleth.idp.authn.duo.impl.DuoPrincipalSerializer" />
            <bean class="net.shibboleth.idp.authn.principal.impl.IdPAttributePrincipalSerializer" />
            <bean class="net.shibboleth.idp.authn.principal.impl.PasswordPrincipalSerializer"
                p:dataSealer="#{'%{idp.sealer.storeResource:}'.trim().length() > 0 ? getObject('shibboleth.DataSealer') : null}" />
        </list>
     </property>
</bean>
```

### 3. Modify attribute-resolver.xml

After enabling the serializers, you're able to read the corresponding principals' contents in the attribute resolver. See the example below for reading the information for _eppn_ attribute. The same logic should work for other attributes too.

```
    <resolver:AttributeDefinition id="eppn" xsi:type="ad:Script">
        <AttributeEncoder xsi:type="SAML2ScopedString" name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6"
            friendlyName="eduPersonPrincipalName" encodeType="false" />
        <ad:Script><![CDATA[
          authnContext = resolutionContext.getParent().getSubcontext("net.shibboleth.idp.authn.context.AuthenticationContext");
          subject = authnContext.getAuthenticationResult().getSubject();
          principals = subject.getPrincipals(Java.type("fi.mpass.shibboleth.authn.principal.impl.ShibAttributePrincipal").class);
          iterator = principals.iterator();
          while (iterator.hasNext()) {
              principal = iterator.next();
              if ("eppn".equals(principal.getType())) {
                  eppn.addValue(principal.getValue());
              }
          }
	]]></ad:Script>
```

The filtering of attributes is configured in the similar way as for any Shibboleth IdP attributes in _attribute-filter.xml_.
