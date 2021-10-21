/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.cscommon.enums;

/**
 *
 * @author stefan
 */
public enum SigTaskStatus {

    Received(0), Serviced(1), DuplicateUserReq(2);
    private int id;

    private SigTaskStatus(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }

    public static SigTaskStatus getStatus(int id) {
        SigTaskStatus[] values = values();
        for (SigTaskStatus status : values) {
            if (status.getId() == id) {
                return status;
            }
        }
        return null;
    }
}
