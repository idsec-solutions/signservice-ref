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
package com.aaasec.sigserv.cscommon.metadata;

import oasisNamesTcSAMLMetadataUi.UIInfoType;

/**
 * MDUI extension content.
 */
public class MduiExtVal {
    public EntityType entityType;
    public UIInfoType mduiExt;

    public MduiExtVal(EntityType entityType, UIInfoType nduiExt) {
        this.entityType = entityType;
        this.mduiExt = nduiExt;
    }        
}
