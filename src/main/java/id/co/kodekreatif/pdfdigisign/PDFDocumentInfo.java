package id.co.kodekreatif.pdfdigisign;
import java.util.ArrayList;
/**
 * A structure holding digital signatures information in a PDF file.
 * If no signatures is available, then signatures list would be empty.
 */
public class PDFDocumentInfo {
  public ArrayList<SignatureInfo> signatures = new ArrayList<SignatureInfo>();
}
