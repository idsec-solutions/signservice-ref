/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.aaasec.sigserv.sigauthsp.models;

import se.elegnamnden.id.csig.x11.dssExt.ns.SignMessageDocument;
import se.elegnamnden.id.csig.x11.sap.ns.SADRequestDocument;
import se.swedenconnect.id.authn.x10.principalSelection.ns.PrincipalSelectionDocument;

import java.util.List;

/**
 * @author stefan
 */
public class AuthReqData {

  private RequestType type;
  private String idpEntityId;
  private String spEntityId;
  private SignMessageDocument signMessage;
  private SADRequestDocument sadRequest;
  private PrincipalSelectionDocument principalSelection;
  private List<String> loa;
  private boolean forceAuthn;
  private KeyStoreBundle ksBundle;
  private String reqUrl;
  private boolean persistentId;
  private String id;

  public AuthReqData() {
  }

  public AuthReqData(RequestType type, String idpEntityId, String spEntityId,
    SignMessageDocument signMessage, SADRequestDocument sadRequest,
    PrincipalSelectionDocument principalSelection, List<String> loa, boolean forceAuthn,
    KeyStoreBundle ksBundle, String reqUrl, boolean persistentId, String id) {
    this.type = type;
    this.idpEntityId = idpEntityId;
    this.spEntityId = spEntityId;
    this.signMessage = signMessage;
    this.sadRequest = sadRequest;
    this.principalSelection = principalSelection;
    this.loa = loa;
    this.forceAuthn = forceAuthn;
    this.ksBundle = ksBundle;
    this.reqUrl = reqUrl;
    this.persistentId = persistentId;
    this.id = id;
  }

  public AuthReqData(RequestType type, String idpEntityId, String spEntityId, SignMessageDocument signMessage, List<String> loa,
    boolean forceAuthn, KeyStoreBundle ksBundle, String reqUrl) {
    this.type = type;
    this.idpEntityId = idpEntityId;
    this.spEntityId = spEntityId;
    this.signMessage = signMessage;
    this.loa = loa;
    this.forceAuthn = forceAuthn;
    this.ksBundle = ksBundle;
    this.reqUrl = reqUrl;
    this.persistentId = false;
    this.id = null;
    this.principalSelection = null;
  }

  public RequestType getType() {
    return type;
  }

  public void setType(RequestType type) {
    this.type = type;
  }

  public String getIdpEntityId() {
    return idpEntityId;
  }

  public void setIdpEntityId(String idpEntityId) {
    this.idpEntityId = idpEntityId;
  }

  public String getSpEntityId() {
    return spEntityId;
  }

  public void setSpEntityId(String spEntityId) {
    this.spEntityId = spEntityId;
  }

  public SignMessageDocument getSignMessage() {
    return signMessage;
  }

  public void setSignMessage(SignMessageDocument signMessage) {
    this.signMessage = signMessage;
  }

  public List<String> getLoa() {
    return loa;
  }

  public void setLoa(List<String> loa) {
    this.loa = loa;
  }

  public boolean isForceAuthn() {
    return forceAuthn;
  }

  public void setForceAuthn(boolean forceAuthn) {
    this.forceAuthn = forceAuthn;
  }

  public KeyStoreBundle getKsBundle() {
    return ksBundle;
  }

  public void setKsBundle(KeyStoreBundle ksBundle) {
    this.ksBundle = ksBundle;
  }

  public String getReqUrl() {
    return reqUrl;
  }

  public void setReqUrl(String reqUrl) {
    this.reqUrl = reqUrl;
  }

  public boolean isPersistentId() {
    return persistentId;
  }

  public void setPersistentId(boolean persistentId) {
    this.persistentId = persistentId;
  }

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public SADRequestDocument getSadRequest() {
    return sadRequest;
  }

  public void setSadRequest(SADRequestDocument sadRequest) {
    this.sadRequest = sadRequest;
  }

  public PrincipalSelectionDocument getPrincipalSelection() {
    return principalSelection;
  }

  public void setPrincipalSelection(PrincipalSelectionDocument principalSelection) {
    this.principalSelection = principalSelection;
  }
}
