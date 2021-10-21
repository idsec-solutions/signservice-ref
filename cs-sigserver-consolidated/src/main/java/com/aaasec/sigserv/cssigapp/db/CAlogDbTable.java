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
 * Log database.
 */
import com.aaasec.sigserv.cssigapp.data.DbCALog;
import java.util.logging.Level;
import java.sql.*;
import java.util.List;
import java.util.logging.Logger;

public class CAlogDbTable extends SqliteUtil<DbCALog> {

    public static final String DATA_TABLE = "Log";
    private static final String KEY_COL = "Log_Date";
    private static final String TABLE_CONSTRUCT =
            "Log_Date BIGINT,"
            + "Event VARCHAR(255),"
            + "Code INTEGER not NULL,"
            + "Parameter VARCHAR(65535),";

    public CAlogDbTable(String dbFileName) {
        super(dbFileName, TABLE_CONSTRUCT, DATA_TABLE, KEY_COL);
    }

    @Override
    PreparedStatement dataStoragePreparedStatement(Connection con, DbCALog dbLog, boolean replace) {
        String action = (replace) ? "INSERT OR REPLACE" : "INSERT";
        PreparedStatement prep = null;

        try {
            prep = con.prepareStatement(
                    action + " INTO " + table + " VALUES (?,?,?,?);");
            prep.setLong(1, dbLog.getLogTime());
            prep.setString(2, dbLog.getEventString());
            prep.setLong(3, dbLog.getLogCode());
            prep.setString(4, dbLog.getLogParameter());
        } catch (SQLException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }

        return prep;
    }

    @Override
    void processDatabaseRecordValues(ResultSet rs, List<DbCALog> valueList) {
        try {
            while (rs.next()) {
                DbCALog logData = new DbCALog();
                logData.setLogTime(rs.getLong(1));
                logData.setEventString(rs.getString(2));
                logData.setLogCode(rs.getInt(3));
                logData.setLogParameter(rs.getString(4));
                valueList.add(logData);
            }
            rs.close();
        } catch (SQLException ex) {
            Logger.getLogger(CAlogDbTable.class.getName()).log(Level.WARNING, null, ex);
        }
    }

    @Override
    String getKeyColumnStringValue(DbCALog tr) {
        return String.valueOf(tr.getLogTime());
    }
}
