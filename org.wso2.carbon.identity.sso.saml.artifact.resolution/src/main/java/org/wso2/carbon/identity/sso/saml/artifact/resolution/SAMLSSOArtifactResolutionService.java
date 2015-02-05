/*
*  Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.wso2.carbon.identity.sso.saml.artifact.resolution;


import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.artifact.resolution.builders.SamlArtifactResponseBuilder;
import org.wso2.carbon.identity.sso.saml.cache.CacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOArtifactCache;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOArtifactCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOArtifactCacheKey;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSORespDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import javax.xml.stream.XMLStreamException;

public class SAMLSSOArtifactResolutionService {

    private static Log log = LogFactory.getLog(SAMLSSOArtifactResolutionService.class);

    /**
     * Receives the SOAP message containing the <ArtifactResolve>
     * @param omElement
     * @return
     * @throws IdentityException
     * @throws XMLStreamException
     */
    public OMElement resolveArtifact(OMElement omElement) throws IdentityException, XMLStreamException {

        String xmlString = omElement.toString();
        ArtifactResolve artifactResolve = (ArtifactResolve)SAMLSSOUtil.unmarshall(xmlString);

        SAMLSSORespDTO samlssoRespDTO = null;

        if(artifactResolve.getArtifact() != null) {
            Artifact artifact = artifactResolve.getArtifact();
            String artifactStr = artifact.getArtifact();

            if(artifactStr != null) {

                // Get SAMLSSORespDTO from the cache
                SAMLSSOArtifactCacheKey key = new SAMLSSOArtifactCacheKey(artifactStr);
                CacheEntry cacheEntry = SAMLSSOArtifactCache.getInstance(0).getValueFromCache(key);

                if(cacheEntry != null) {
                    samlssoRespDTO = ((SAMLSSOArtifactCacheEntry)cacheEntry).getSamlssoRespDTO();
                    // To ensure One-Time-Use property of the artifact
                    SAMLSSOArtifactCache.getInstance(0).clearCacheEntry(key);
                    if (log.isDebugEnabled()) {
                        log.debug("Cache Entry Cleared for the Received Artifact");
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Cache Entry Not Found for the Received Artifact");
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Invalid Artifact");
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Invalid Artifact Resolve.");
            }
        }

        // Build the <ArtifactResponse>
        SamlArtifactResponseBuilder artifactResponseBuilder = new SamlArtifactResponseBuilder();
        XMLObject artifactResponse = artifactResponseBuilder.buildArtifactResponse(artifactResolve, samlssoRespDTO);
        String xml = SAMLSSOUtil.marshall(artifactResponse);

        OMElement responseElement = AXIOMUtil.stringToOM(xml);
        return responseElement;
    }
}
