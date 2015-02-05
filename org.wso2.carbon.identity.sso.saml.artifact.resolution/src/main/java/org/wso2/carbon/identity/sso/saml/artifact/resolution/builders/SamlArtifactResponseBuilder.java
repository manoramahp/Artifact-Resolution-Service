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

package org.wso2.carbon.identity.sso.saml.artifact.resolution.builders;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.ArtifactResponseBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.util.Base64;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.artifact.resolution.processors.ArtifactResolveProcessor;
import org.wso2.carbon.identity.sso.saml.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.sso.saml.builders.signature.SSOSigner;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSORespDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

public class SamlArtifactResponseBuilder {

    private static Log log = LogFactory.getLog(SamlArtifactResponseBuilder.class);

    /**
     * Build the <ArtifactResponse> for a valid or invalid Artifact
     * In both cases;
     * <Status> element MUST include a <StatusCode> with the value urn:oasis:names:tc:SAML:2.0:status:Success

     * @param artifactResolve
     * @param samlssoRespDTO
     * @return
     * @throws IdentityException
     */
    public ArtifactResponse buildArtifactResponse(ArtifactResolve artifactResolve, SAMLSSORespDTO samlssoRespDTO) throws IdentityException {

        if (log.isDebugEnabled()) {
            log.debug("Generating the Artifact Response...");
        }

        ArtifactResponse  artifactResponse = new ArtifactResponseBuilder().buildObject();
        artifactResponse.setID(SAMLSSOUtil.createID());
        artifactResponse.setInResponseTo(artifactResolve.getID());
        artifactResponse.setIssuer(SAMLSSOUtil.getIssuer());
        artifactResponse.setIssueInstant(new DateTime());
        artifactResponse.setVersion(SAMLVersion.VERSION_20);

        Status status = new StatusBuilder().buildObject();
        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue(SAMLSSOConstants.StatusCodes.SUCCESS_CODE);
        status.setStatusCode(statusCode);
        artifactResponse.setStatus(status);

        boolean isValidArtifactResolve = new ArtifactResolveProcessor().process(artifactResolve);

        if(samlssoRespDTO != null && isValidArtifactResolve) {
            String samlResponse = samlssoRespDTO.getRespString();
            String decodedSamlResponse = new String(Base64.decode(samlResponse));
            Response unmarshalledResponse = (Response) SAMLSSOUtil.unmarshall(decodedSamlResponse);
            artifactResponse.setMessage(unmarshalledResponse);

            signArtifactResponse(artifactResponse, XMLSignature.ALGO_ID_SIGNATURE_RSA,
                    new SignKeyDataHolder(samlssoRespDTO.getSubject()));
        }

        return artifactResponse;
    }

    /**
     * Sign SAML Artifact Response
     * @param response
     * @param signatureAlgorithm
     * @param cred
     * @throws IdentityException
     */
    private void signArtifactResponse(StatusResponseType response, String signatureAlgorithm,
                                                           X509Credential cred) throws IdentityException{

        try {
            SSOSigner ssoSigner;
            synchronized (Runtime.getRuntime().getClass()){
                ssoSigner = (SSOSigner)Class.forName(IdentityUtil.getProperty(
                        "SSOService.SAMLSSOSigner").trim()).newInstance();
                ssoSigner.init();
            }

            ssoSigner.doSignResponse(response, signatureAlgorithm, cred);

        } catch (ClassNotFoundException e) {
            throw new IdentityException("Class not found: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
        } catch (InstantiationException e) {
            throw new IdentityException("Error while instantiating class: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
        } catch (IllegalAccessException e) {
            throw new IdentityException("Illegal access to class: "
                    + IdentityUtil.getProperty("SSOService.SAMLSSOSigner"), e);
        } catch (Exception e) {
            throw new IdentityException("Error while signing the SAML Artifact Response message.", e);
        }

    }

}
