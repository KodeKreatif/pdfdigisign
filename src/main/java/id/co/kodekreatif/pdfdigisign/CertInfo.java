package id.co.kodekreatif.pdfdigisign;

import java.util.ArrayList;
import java.util.Date;
/**
 * A structure holding certificate information.
 **/
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
  public boolean valid = false;
  public ArrayList<String> problems = new ArrayList<String>();

  public Date notBefore;
  public Date notAfter;

  public boolean selfSigned = false;
}
