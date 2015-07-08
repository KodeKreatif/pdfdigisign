package id.co.kodekreatif.pdfdigisign;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import id.co.kodekreatif.pdfdigisign.*;

class GenericCheckInfo {
  public PDFDocumentInfo info = null;
  public int status = -1;
}

public class VerificatorTest {

  public GenericCheckInfo generic(String path) {
    GenericCheckInfo info = new GenericCheckInfo();
    Verificator v = new Verificator(path);
    try {
      PDFDocumentInfo i = v.validate();
      info.status = 0;
      info.info = i;
    } catch (IOException e) {
      e.printStackTrace();
      info.status = 1;
    } catch (CertificateException e) {
      info.status = 2;
    } catch (KeyStoreException e) {
      info.status = 3;
    } catch (NoSuchAlgorithmException e) {
      info.status = 4;
    }
    return info;
  }

  @Test
  public void testNoSignature() {
    GenericCheckInfo i = generic("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/no-signature.pdf");
    assertEquals("Verification must be successful", i.status, 0);
    assertEquals("Signature must not exist", i.info.hasSignature, false);
  }

  @Test
  public void testSimpleSignature() {
    GenericCheckInfo i = generic("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/simple-signature.pdf");
    assertEquals("Verification must be successful", i.status, 0);
    assertEquals("Signature must not exist", i.info.hasSignature, true);
  }

  @Test
  public void testTwoSignatures() {
    GenericCheckInfo i = generic("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/two-signatures.pdf");
    assertEquals("Verification must be successful", i.status, 0);
    assertEquals("Signature must not exist", i.info.hasSignature, true);
    assertEquals("Signature length must be two", i.info.certs.size(), 3);
  }


}
