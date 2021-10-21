/*
 * Copyright 2013 Swedish E-identification Board (E-legitimationsnämnden)
 *  		 
 *   Licensed under the EUPL, Version 1.1 or ñ as soon they will be approved by the 
 *   European Commission - subsequent versions of the EUPL (the "Licence");
 *   You may not use this work except in compliance with the Licence. 
 *   You may obtain a copy of the Licence at:
 * 
 *   http://joinup.ec.europa.eu/software/page/eupl 
 * 
 *   Unless required by applicable law or agreed to in writing, software distributed 
 *   under the Licence is distributed on an "AS IS" basis,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or 
 *   implied.
 *   See the Licence for the specific language governing permissions and limitations 
 *   under the Licence.
 */
package com.aaasec.sigserv.cscommon.enums;

/**
 * Document type enumeration
 */
public enum SigDocumentType {

    XML("text/xml;charset=UTF-8", ".xml", false, ""),
    PDF("application/pdf", ".pdf", true, "http://elegnamnsen.se/identifiers/csig/transforms/pdfcms"),
    Unknown("","",false,"");
    private String mimeType;
    private String fileSuffix;
    private boolean transform;
    private String transformURI;

    private SigDocumentType(String mimeType, String fileSuffix, boolean transform, String transformURI) {
        this.mimeType = mimeType;
        this.fileSuffix = fileSuffix;
        this.transform = transform;
        this.transformURI = transformURI;
    }

    public String getMimeType() {
        return mimeType;
    }

    public String getFileSuffix() {
        return fileSuffix;
    }

    public boolean isTransform() {
        return transform;
    }

    public String getTransformURI() {
        return transformURI;
    }
}
