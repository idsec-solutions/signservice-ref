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
 * Key store database.
 */
import com.aaasec.sigserv.cssigapp.data.DbKeyStore;
import java.util.logging.Level;
import java.sql.*;
import java.util.List;
import java.util.logging.Logger;

public class KeyStoreTable extends SqliteUtil<DbKeyStore> {

    public static final String DATA_TABLE = "KeyStores";
    private static final String KEY_COL = "ID";
    private static final String TABLE_CONSTRUCT =
            "ID VARCHAR(255) not NULL,"
            + "Date BIGINT,"
            + "Reserver VARCHAR(255),";

    public KeyStoreTable(String dbFileName) {
        super(dbFileName, TABLE_CONSTRUCT, DATA_TABLE, KEY_COL);
    }

    @Override
    PreparedStatement dataStoragePreparedStatement(Connection con, DbKeyStore ks, boolean replace) {
        String action = (replace) ? "INSERT OR REPLACE" : "INSERT";
        PreparedStatement prep = null;

        try {
            prep = con.prepareStatement(
                    action + " INTO " + table + " VALUES (?,?,?);");
            prep.setString(1, ks.getId());
            prep.setLong(2, ks.getTime());
            prep.setString(3, ks.getReserverID());
        } catch (SQLException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }

        return prep;
    }

    @Override
    void processDatabaseRecordValues(ResultSet rs, List<DbKeyStore> valueList) {
        try {
            while (rs.next()) {
                    DbKeyStore ks = new DbKeyStore();
                    ks.setId(rs.getString(1));
                    ks.setTime(rs.getLong(2));
                    ks.setReserverID(rs.getString(3));
                valueList.add(ks);
            }
            rs.close();
        } catch (SQLException ex) {
            Logger.getLogger(KeyStoreTable.class.getName()).log(Level.WARNING, null, ex);
        }
    }

    @Override
    String getKeyColumnStringValue(DbKeyStore tr) {
        return tr.getId();
    }
        
}
