package id.co.kodekreatif.pdfdigisign;
import java.util.ArrayList;

/**
 * A structure holding a digital signature information.
 **/
public class SignatureInfo {
  /**
   * Holds all certificates used to sign this signature
   */
  public ArrayList<CertInfo> certs = new ArrayList<CertInfo>();

  /**
   * Name of the person made the signature
   */
  public String name = "";

  /**
   * Modification information
   */
  public String modified = "";

  /**
   * Place where signature was made
   */
  public String location = "";

  /**
   * Reasoning of the signature
   */
  public String reason = "";

  /**
   * Contact info regarding the signature
   */
  public String contactInfo = "";
}
