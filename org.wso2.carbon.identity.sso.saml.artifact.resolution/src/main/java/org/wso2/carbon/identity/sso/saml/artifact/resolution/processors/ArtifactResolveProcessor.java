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

package org.wso2.carbon.identity.sso.saml.artifact.resolution.processors;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.builders.signature.SSOSigner;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

public class ArtifactResolveProcessor {

    private static Log log = LogFactory.getLog(ArtifactResolveProcessor.class);

    /**
     * Process and validate the <ArtifactResolve> according to the SAML Specification
     * @param artifactResolve ArtifactResolve
     * @return
     */
    public boolean process(ArtifactResolve artifactResolve) throws IdentityException {

        // TODO authenticate the sender
        // Cannot authenticate the issuer as the original intended SAML Response recipient -> invalid
        if(artifactResolve.getIssuer() == null || artifactResolve.getIssuer().getValue() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Validation Failed. Issuer Empty");
            }
            return false;
        }


        if (!(artifactResolve.getVersion().equals(SAMLVersion.VERSION_20))) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid SAML Version : " + artifactResolve.getVersion());
            }
            return false;
        } else if(artifactResolve.getArtifact() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Validation Failed. Artifact Empty");
            }
            return false;
        } else if(artifactResolve.getArtifact().getArtifact() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Validation Failed. Artifact Empty");
            }
            return false;
        } else {
            String domainName = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            String alias = "wso2carbon";
            return validateXMLSignature(artifactResolve, alias, domainName);
        }
    }


    /**
     * Validate the signature of Artifact Resolve
     *
     * @param request Artifact Resolve
     * @param alias Certificate alias against which the signature is validated.
     * @param domainName domain name of the subject
     * @return true, if the signature is valid.
     */
    public boolean validateXMLSignature(RequestAbstractType request, String alias,
                                               String domainName) throws IdentityException {

        boolean isSignatureValid = false;

        if (request.getSignature() != null) {
            try {
                X509Credential cred = SAMLSSOUtil.getX509CredentialImplForTenant(domainName, alias);
                SSOSigner ssoSigner;
                synchronized (Runtime.getRuntime().getClass()){
                    ssoSigner = (SSOSigner)Class.forName(IdentityUtil.getProperty(
                            "SSOService.SAMLSSOSigner").trim()).newInstance();
                    ssoSigner.init();
                }

                return ssoSigner.doValidateXMLSignature(request, cred, alias);
            } catch (IdentitySAML2SSOException ignore) {
                log.warn("Signature validation failed for the SAML Artifact Resolve Message : Failed to construct the X509CredentialImpl for the alias " +
                        alias);
                log.debug(ignore);
            } catch (IdentityException ignore) {
                log.warn("Signature Validation Failed for the SAML Artifact Resolve : Signature is invalid.");
                log.debug(ignore);
            } catch (ClassNotFoundException e) {
                throw new IdentityException("Class not found: "
                        + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
            } catch (InstantiationException e) {
                throw new IdentityException("Error while instantiating class: "
                        + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
            } catch (IllegalAccessException e) {
                throw new IdentityException("Illegal access to class: "
                        + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
            }catch (Exception e){

            }
        }
        return isSignatureValid;
    }
}
