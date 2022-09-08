package com.aaasec.sigserv.xmlsign;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SimplePkiCredential {

  private PrivateKey privateKey;
  private List<X509Certificate> chain;

  public SimplePkiCredential(List<X509Certificate> chain, PrivateKey privateKey) {
    this.privateKey = privateKey;
    this.chain = chain;
  }

  public PublicKey getPublicKey() {
    return chain.get(0).getPublicKey();
  }

  public X509Certificate getCertificate() {
    return chain.get(0);
  }

  public void setCertificate(X509Certificate x509Certificate) {
    chain = Collections.singletonList(x509Certificate);
  }

  public List<X509Certificate> getCertificateChain() {
    return chain;
  }

  public void setCertificateChain(List<X509Certificate> list) {
    this.chain = list;
  }

  public PrivateKey getPrivateKey() {
    return privateKey;
  }

  public String getName() {
    return this.getClass().getSimpleName();
  }

  public void destroy() throws Exception {
  }

  public void afterPropertiesSet() throws Exception {
  }
}
