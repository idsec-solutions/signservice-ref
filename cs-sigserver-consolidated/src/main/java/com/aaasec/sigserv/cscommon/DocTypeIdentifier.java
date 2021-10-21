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
package com.aaasec.sigserv.cscommon;

import com.aaasec.sigserv.cscommon.enums.SigDocumentType;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.apache.commons.io.IOUtils;

/**
 * Factory class determining and returning an appropriate signature validation
 * object for a given document.
 */
public class DocTypeIdentifier {

    /**
     * Guess the document format and return an appropriate document type string
     *
     * @param docBytes the bytes of the document the document
     * @return "xml" if the document is an XML document or "pdf" if the document
     * is a PDF document, or else an error message.
     */
    public static SigDocumentType getDocType(byte[] docBytes) {
        InputStream is = new ByteArrayInputStream(docBytes);
        return getDocType(is);

    }

    /**
     * Guess the document format and return an appropriate document type string
     *
     * @param docFile A file holding the document
     * @return "xml" if the document is an XML document or "pdf" if the document
     * is a PDF document, or else an error message.
     */
    public static SigDocumentType getDocType(File docFile) {
        try {
            InputStream is = new FileInputStream(docFile);
            return getDocType(is);
        } catch (FileNotFoundException ex) {
            return SigDocumentType.Unknown;
        }
    }

    /**
     * Guess the document format and return an appropriate document type string
     *
     * @param is An InputStream holding the document
     * @return "xml" if the document is an XML document or "pdf" if the document
     * is a PDF document, or else an error message.
     */
    public static SigDocumentType getDocType(InputStream is) {
        InputStream input = null;

        try {
            input = new BufferedInputStream(is);
            input.mark(5);
            byte[] preamble = new byte[5];
            int read = 0;
            try {
                read = input.read(preamble);
                input.reset();
            } catch (IOException ex) {
                return SigDocumentType.Unknown;
            }
            if (read < 5) {
                return SigDocumentType.Unknown;
            }
            String preambleString = new String(preamble);
            byte[] xmlPreable = new byte[]{'<', '?', 'x', 'm', 'l'};
            byte[] xmlUtf8 = new byte[]{-17, -69, -65, '<', '?'};
            if (Arrays.equals(preamble, xmlPreable) || Arrays.equals(preamble, xmlUtf8)) {
                return SigDocumentType.XML;
            } else if (preambleString.equals("%PDF-")) {
                return SigDocumentType.PDF;
            } else if (preamble[0] == 'P' && preamble[1] == 'K') {
                ZipInputStream asics = new ZipInputStream(new BufferedInputStream(is));
                ByteArrayOutputStream datafile = null;
                ByteArrayOutputStream signatures = null;
                ZipEntry entry;
                try {
                    while ((entry = asics.getNextEntry()) != null) {
                        if (entry.getName().equals("META-INF/signatures.p7s")) {
                            signatures = new ByteArrayOutputStream();
                            IOUtils.copy(asics, signatures);
                            signatures.close();
                        } else if (entry.getName().equalsIgnoreCase("META-INF/signatures.p7s")) {
                            /* Wrong case */
                            // asics;Non ETSI compliant
                            return SigDocumentType.Unknown;
                        } else if (entry.getName().indexOf("/") == -1) {
                            if (datafile == null) {
                                datafile = new ByteArrayOutputStream();
                                IOUtils.copy(asics, datafile);
                                datafile.close();
                            } else {
//                              // asics;ASiC-S profile support only one data file
                                return SigDocumentType.Unknown;
                            }
                        }
                    }
                } catch (Exception ex) {
                    // null;Invalid ASiC-S
                    return SigDocumentType.Unknown;
                }
                if (datafile == null || signatures == null) {
                    // asics;ASiC-S profile support only one data file with CAdES signature
                    return SigDocumentType.Unknown;
                }
                // asics/cades
                return SigDocumentType.Unknown;

            } else if (preambleString.getBytes()[0] == 0x30) {
                // cades;
                return SigDocumentType.Unknown;
            } else {
                // null;Document format not recognized/handled
                return SigDocumentType.Unknown;
            }
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (IOException e) {
                }
            }
        }
    }
}