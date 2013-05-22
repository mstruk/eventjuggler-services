/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.eventjuggler.services.idb.model;

import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Entity
@XmlRootElement
public class Application {

    private String callbackUrl;

    @Id
    private String key;

    private String name;

    private String owner;

    private String javaScriptOrigin;

    @OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    private List<IdentityProviderConfig> providers;

    private String secret;

    public String getCallbackUrl() {
        return callbackUrl;
    }

    public String getKey() {
        return key;
    }

    public String getName() {
        return name;
    }

    public String getOwner() {
        return owner;
    }

    public String getJavaScriptOrigin() {
        return javaScriptOrigin;
    }

    public List<IdentityProviderConfig> getProviders() {
        return providers;
    }

    public String getSecret() {
        return secret;
    }

    public void setCallbackUrl(String callbackUrl) {
        this.callbackUrl = callbackUrl;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public void setJavaScriptOrigin(String javaScriptOrigin) {
        this.javaScriptOrigin = javaScriptOrigin;
    }

    public void setProviders(List<IdentityProviderConfig> providers) {
        this.providers = providers;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

}
