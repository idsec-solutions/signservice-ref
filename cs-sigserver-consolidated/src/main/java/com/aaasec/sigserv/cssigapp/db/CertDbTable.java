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
package com.aaasec.sigserv.cssigapp.db;

/**
 * Certificate database.
 */
import com.aaasec.sigserv.cssigapp.data.DbCert;
import java.util.logging.Level;
import java.sql.*;
import java.util.List;
import java.util.logging.Logger;

public class CertDbTable extends SqliteUtil<DbCert> {

    public static final String DATA_TABLE = "Certificates";
    private static final String KEY_COL = "Issue_Date";
    private static final String TABLE_CONSTRUCT =
            "Issue_Date BIGINT,"
            + "Serial VARCHAR(255) not NULL,"
            + "Certificate VARCHAR(65535),"
            + "Revoked INTEGER,"
            + "Revoke_Date BIGINT,";

    public CertDbTable(String dbFileName) {
        super(dbFileName, TABLE_CONSTRUCT, DATA_TABLE, KEY_COL);
    }

    @Override
    PreparedStatement dataStoragePreparedStatement(Connection con, DbCert dbCert, boolean replace) {
        String action = (replace) ? "INSERT OR REPLACE" : "INSERT";
        PreparedStatement prep = null;

        try {
            prep = con.prepareStatement(
                    action + " INTO " + table + " VALUES (?,?,?,?,?);");
            prep.setLong(1, dbCert.getIssueDate());
            prep.setString(2, dbCert.getSerialStr());
            prep.setString(3, dbCert.getPemCert());
            prep.setInt(4, dbCert.getRevoked());
            prep.setLong(5, dbCert.getRevDate());
        } catch (SQLException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }

        return prep;
    }

    @Override
    void processDatabaseRecordValues(ResultSet rs, List<DbCert> valueList) {
        try {
            while (rs.next()) {
                DbCert certData = new DbCert();
                certData.setIssueDate(rs.getLong(1));
                certData.setSerial(rs.getString(2));
                certData.setPemCert(rs.getString(3));
                certData.setRevoked(rs.getInt(4));
                certData.setRevDate(rs.getLong(5));
                valueList.add(certData);
            }
            rs.close();
        } catch (SQLException ex) {
            Logger.getLogger(CertDbTable.class.getName()).log(Level.WARNING, null, ex);
        }
    }

    @Override
    String getKeyColumnStringValue(DbCert tr) {
        return String.valueOf(tr.getIssueDate());
    }
    
    public List<DbCert> getCertsByRevocation(boolean revoked){
        String rev = revoked?"1":"0";
        return getRecords("Revoked", rev);
    }
    
}
