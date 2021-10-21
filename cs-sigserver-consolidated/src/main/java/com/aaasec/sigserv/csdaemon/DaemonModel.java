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
package com.aaasec.sigserv.csdaemon;

import com.aaasec.sigserv.cscommon.FileOps;
import com.aaasec.sigserv.cscommon.FilenameFilterImpl;
import com.aaasec.sigserv.cscommon.config.ConfigFactory;
import com.aaasec.sigserv.csdaemon.ca.RootCaConfig;
import com.aaasec.sigserv.csdaemon.ca.RootCaFactory;
import com.aaasec.sigserv.csdaemon.ca.RootCertificationAuthority;
import com.aaasec.sigserv.cssigapp.ca.CAFactory;
import com.aaasec.sigserv.cssigapp.ca.CertificationAuthority;
import com.aaasec.sigserv.cssigapp.models.SigServerModel;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Model data for the signature daemon.
 */
public class DaemonModel {

    SigServerModel sigModel;
    RootCaConfig rootConf;
    List<CertificationAuthority> caList = new ArrayList<CertificationAuthority>();
    RootCertificationAuthority rootCa;
    FilenameFilterImpl noLeadingDot = new FilenameFilterImpl(".");

    public DaemonModel() {
        sigModel = new SigServerModel(ContextParameters.getDataLocation());
        ConfigFactory<RootCaConfig> confFact = new ConfigFactory<RootCaConfig>(ContextParameters.getDataLocation(), new RootCaConfig());
        rootConf = confFact.getConfData();

        //Get root CA
        String rootDir = FileOps.getfileNameString(sigModel.getDataLocation(), "RootCA");
        this.rootCa = new RootCertificationAuthority("Central Signing Root", rootDir, sigModel, rootConf, rootConf.getRootKsPassword().toCharArray(), rootConf.getRootKsAlias());
        if (!rootCa.isInitialized()) {
            new RootCaFactory(rootConf).createCa(rootCa);
        }
        reloadCAs();

    }

    public final void reloadCAs() {
        caList.clear();
        //Get the root CA        
        if (rootCa != null) {
            caList.add(rootCa);
        }
        //Get all CAs
        String allCaDirName = FileOps.getfileNameString(sigModel.getDataLocation(), "CA");
        File allCaDir = new File(allCaDirName);
        File[] listFiles = allCaDir.listFiles(noLeadingDot);
        if (listFiles != null && listFiles.length > 0) {
            for (File dir : listFiles) {
                String dirName = dir.getName();
                if (!dirName.startsWith(".")) {
                    CertificationAuthority ca = new CertificationAuthority(dirName, dir.getAbsolutePath(), sigModel, ContextParameters.getConf().getCaKsPassword().toCharArray(), ContextParameters.getConf().getCaKsAlias());
                    if (ca.isInitialized()) {
                        caList.add(ca);
                    }
                }
            }
        } else {
            String signatureCaName = sigModel.getConf().getSignatureCaName();
            if (signatureCaName != null && signatureCaName.length() > 0) {
                String dirName = FileOps.getfileNameString(allCaDirName, signatureCaName);
                CertificationAuthority ca = new CertificationAuthority(signatureCaName, dirName, sigModel, ContextParameters.getConf().getCaKsPassword().toCharArray(), ContextParameters.getConf().getCaKsAlias());
                CAFactory caFact = new CAFactory();
                caFact.createCa(ca);
                caList.add(ca);
            }
        }
    }

    public RootCaConfig getRootConf() {
        return rootConf;
    }

    public SigServerModel getSigModel() {
        return sigModel;
    }

    public RootCertificationAuthority getRootCa() {
        return rootCa;
    }

    public List<CertificationAuthority> getCaList() {
        return caList;
    }

    public void setCaList(List<CertificationAuthority> caList) {
        this.caList = caList;
    }
}
