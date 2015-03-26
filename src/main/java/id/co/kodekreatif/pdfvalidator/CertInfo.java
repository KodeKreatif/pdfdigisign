package id.co.kodekreatif.pdfvalidator;

import java.util.Date;
public class CertInfo {
  public String issuer = "";
  public String subject = "";
  public String serialNumber = "";
  public String signature = "";
  public boolean revoked = false;
  public String revocationPrincipal = "";
  public Date revocationDate = new Date();
  public String revocationReason = "";

  public boolean trusted = false;
  public boolean verified = false;
  public String verificationFailure = "";

  public String state = "invalid";
  public Date notBefore;
  public Date notAfter;

  public boolean selfSigned = false;
}


