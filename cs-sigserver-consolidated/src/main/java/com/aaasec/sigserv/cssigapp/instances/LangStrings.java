/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cssigapp.instances;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 *
 * @author stefan
 */
public class LangStrings {
    Map<String,String> langValues = new HashMap<String, String>();

    public LangStrings(String value, String lang) {
        langValues.put(lang, value);
    }

    public LangStrings(KeyValue[] langVals) {
        for (KeyValue keyVal:langVals){
            langValues.put(keyVal.getKey(), keyVal.getValue());
        }
    }
    public LangStrings(String[] langs, String value) {
        for (String lang:langs){
            langValues.put(lang, value);
        }
    }
    
    public List<String> getLangList(){
        List<String> langList = new ArrayList<String>();
        langList.addAll(langValues.keySet());
        return langList;
    }
    
    public String getVal(String lang){
        if (!langValues.containsKey(lang)){
            return null;
        }
        return langValues.get(lang);
    }

    public Map<String, String> getLangValues() {
        return langValues;
    }
    
}
