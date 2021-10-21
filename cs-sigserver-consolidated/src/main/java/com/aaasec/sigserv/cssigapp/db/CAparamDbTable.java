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
 * Parameters database.
 */
import com.aaasec.sigserv.cssigapp.data.DbCAParam;
import java.util.logging.Level;
import java.sql.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class CAparamDbTable extends SqliteUtil<DbCAParam> {

    public static final String DATA_TABLE = "CA_Data";
    private static final String KEY_COL = "Parameter";
    private static final String TABLE_CONSTRUCT =
            "Parameter VARCHAR(255) not NULL,"
            + "Int_value INTEGER,"
            + "Str_value VARCHAR(255),";

    public CAparamDbTable(String dbFileName) {
        super(dbFileName, TABLE_CONSTRUCT, DATA_TABLE, KEY_COL);
    }

    @Override
    PreparedStatement dataStoragePreparedStatement(Connection con, DbCAParam dbParam, boolean replace) {
        String action = (replace) ? "INSERT OR REPLACE" : "INSERT";
        PreparedStatement prep = null;

        try {
            prep = con.prepareStatement(
                    action + " INTO " + table + " VALUES (?,?,?);");
            prep.setString(1, dbParam.getParamName());
            prep.setLong(2, dbParam.getIntValue());
            prep.setString(3, dbParam.getStrValue());
        } catch (SQLException ex) {
            LOG.log(Level.SEVERE, null, ex);
        }

        return prep;
    }

    @Override
    void processDatabaseRecordValues(ResultSet rs, List<DbCAParam> valueList) {
        try {
            while (rs.next()) {
                    DbCAParam caData = new DbCAParam();
                    caData.setParamName(rs.getString(1));
                    caData.setIntValue(rs.getLong(2));
                    caData.setStrValue(rs.getString(3));
                valueList.add(caData);
            }
            rs.close();
        } catch (SQLException ex) {
            Logger.getLogger(CAparamDbTable.class.getName()).log(Level.WARNING, null, ex);
        }
    }

    @Override
    String getKeyColumnStringValue(DbCAParam tr) {
        return tr.getParamName();
    }
    
    public Map<String,DbCAParam> getParamMap(){
        Map<String,DbCAParam> paramMap = new HashMap<String, DbCAParam>();
        List<DbCAParam> allRecords = getAllRecords();
        for (DbCAParam param:allRecords){
            paramMap.put(param.getParamName(), param);
        }
        return paramMap;
    }
    
}
