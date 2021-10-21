package com.aaasec.sigserv.cscommon.data;

public class AuthnStatus {

  private String statusCode;
  private String childStatusCode;
  private String statusMessage;

  public AuthnStatus() {
  }

  public AuthnStatus(String statusCode, String childStatusCode, String statusMessage) {
    this.statusCode = statusCode;
    this.childStatusCode = childStatusCode;
    this.statusMessage = statusMessage;
  }

  public String getStatusCode() {
    return statusCode;
  }

  public void setStatusCode(String statusCode) {
    this.statusCode = statusCode;
  }

  public String getChildStatusCode() {
    return childStatusCode;
  }

  public void setChildStatusCode(String childStatusCode) {
    this.childStatusCode = childStatusCode;
  }

  public String getStatusMessage() {
    return statusMessage;
  }

  public void setStatusMessage(String statusMessage) {
    this.statusMessage = statusMessage;
  }
}
