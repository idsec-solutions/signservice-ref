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
 * Sign task database.
 */
import com.aaasec.sigserv.cscommon.Base64Coder;
import com.aaasec.sigserv.cscommon.enums.SigTaskStatus;
import com.aaasec.sigserv.cssigapp.data.DbSignTask;
import com.aaasec.sigserv.cssigapp.data.SignAcceptPageInfo;
import com.google.gson.Gson;
import java.util.logging.Level;
import java.sql.*;
import java.util.List;
import java.util.logging.Logger;

public class SignTaskTable extends SqliteUtil<DbSignTask> {

    private static final Gson gson = new Gson();
    public static final String DATA_TABLE = "SignTask";
    private static final String KEY_COL = "ID";
    private static final String TABLE_CONSTRUCT =
            "ID VARCHAR(255) not NULL,"
            + "Time BIGINT,"
            + "Serviced BIGINT,"
            + "Status INT,"
            + "UserIdpId VARCHAR(255),"
            + "Request VARCHAR(65535),"
            + "SignMessage VARCHAR(16777215),"
            + "PageInfo VARCHAR(65535),";

    public SignTaskTable(String dbFileName) {
        super(dbFileName, TABLE_CONSTRUCT, DATA_TABLE, KEY_COL);
    }

    @Override
    PreparedStatement dataStoragePreparedStatement(Connection con, DbSignTask st, boolean replace) {
        String action = (replace) ? "INSERT OR REPLACE" : "INSERT";
        PreparedStatement prep = null;

        try {
            prep = con.prepareStatement(
                    action + " INTO " + table + " VALUES (?,?,?,?,?,?,?,?);");
            prep.setString(1, st.getId());
            prep.setLong(2, st.getTime());
            prep.setLong(3, st.getServiced());
            prep.setInt(4, st.getStatus().getId());
            prep.setString(5, st.getUserIdpId());
            prep.setString(6, toB64(st.getRequest()));
            prep.setString(7, toB64(st.getSignMessage()));
            prep.setString(8, gson.toJson(st.getPageInfo()));
        } catch (SQLException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }

        return prep;
    }

    @Override
    void processDatabaseRecordValues(ResultSet rs, List<DbSignTask> valueList) {
        try {
            while (rs.next()) {
                DbSignTask ks = new DbSignTask();
                ks.setId(rs.getString(1));
                ks.setTime(rs.getLong(2));
                ks.setServiced(rs.getLong(3));
                ks.setStatus(SigTaskStatus.getStatus(rs.getInt(4)));
                ks.setUserIdpId(rs.getString(5));
                ks.setRequest(fromB64(rs.getString(6)));
                ks.setSignMessage(fromB64(rs.getString(7)));
                ks.setPageInfo(gson.fromJson(rs.getString(8), SignAcceptPageInfo.class));
                valueList.add(ks);
            }
            rs.close();
        } catch (SQLException ex) {
            Logger.getLogger(SignTaskTable.class.getName()).log(Level.WARNING, null, ex);
        }
    }

    @Override
    String getKeyColumnStringValue(DbSignTask tr) {
        return tr.getId();
    }

    private String toB64(byte[] data) {
        if (data == null) {
            return "";
        }
        return String.valueOf(Base64Coder.encode(data));
    }

    private byte[] fromB64(String str) {
        return Base64Coder.decode(str);
    }
}
