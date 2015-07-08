package id.co.kodekreatif.pdfdigisign;
import java.util.ArrayList;
public class PDFDocumentInfo {
  public ArrayList<CertInfo> certs = new ArrayList<CertInfo>();

  public boolean hasSignature = false;
  public String name = "";
  public String modified = "";
  public String location = "";
  public String reason = "";
  public String contactInfo = "";

}


