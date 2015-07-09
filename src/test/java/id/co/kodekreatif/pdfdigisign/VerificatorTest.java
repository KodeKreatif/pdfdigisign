package id.co.kodekreatif.pdfdigisign;

import java.io.IOException;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.NoSuchAlgorithmException;
import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.assertEquals;
import id.co.kodekreatif.pdfdigisign.*;


class GenericCheckInfo {
  public PDFDocumentInfo info = null;
  public int status = -1;
}

class TestKeyStore {
  public KeyStore store = null;

  public TestKeyStore() {
    try {
      store = KeyStore.getInstance(KeyStore.getDefaultType());
      store.load(null, null);
    } catch(Exception e) {
      e.printStackTrace();
    }
  }

  public boolean addCertificate(String alias, String path) {
    try {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      FileInputStream stream = new FileInputStream(path);
      X509Certificate cert = (X509Certificate) factory.generateCertificate(stream);
      store.setCertificateEntry(alias, cert);
      return true;
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    }
  }
}

public class VerificatorTest {
  TestKeyStore testKeyStore = null;

  @Before
  public void initKeyStore() {
    if (testKeyStore == null) {
      testKeyStore = new TestKeyStore();
    }
  }

  public GenericCheckInfo generic(Verificator v) {
    GenericCheckInfo info = new GenericCheckInfo();
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
    Verificator v = new Verificator("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/no-signature.pdf");
    GenericCheckInfo i = generic(v);
    assertEquals("Verification must be successful", i.status, 0);
    assertEquals("Signature must exist", i.info.signatures.size(), 0);
  }

  @Test
  public void testSimpleSignature() {
    Verificator v = new Verificator("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/simple-signature.pdf");
    GenericCheckInfo i = generic(v);
    assertEquals("Verification must be successful", i.status, 0);
    assertEquals("Signature must exist", i.info.signatures.size(), 1);
  }

  @Test
  public void testTwoSignatures() {
    Verificator v = new Verificator("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/two-signatures.pdf");
    GenericCheckInfo i = generic(v);
    assertEquals("Verification must be successful", i.status, 0);
    assertEquals("Signature length must be two", i.info.signatures.size(), 2);
  }

  @Test
  public void testNotTrustedSignature() {
    Verificator v = new Verificator("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/simple-signature.pdf");
    v.setKeyStore(testKeyStore.store);
    GenericCheckInfo i = generic(v);

    assertEquals("Verification must be successful", i.status, 0);
    assertEquals("Signature must exist", i.info.signatures.size(), 1);
    assertEquals("Cert must be trusted", ((i.info.signatures.get(0)).certs.get(0)).trusted, false);
    assertEquals("Cert must be verified", ((i.info.signatures.get(0)).certs.get(0)).verified, true);
  }


  @Test
  public void testTrustedSignature() {
    Verificator v = new Verificator("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/simple-signature.pdf");
    boolean added = testKeyStore.addCertificate("alias1", "./src/test/java/id/co/kodekreatif/pdfdigisign/assets/ca-test.pem");
    assertEquals("Cert addition must be successful", true, added);
    v.setKeyStore(testKeyStore.store);
    GenericCheckInfo i = generic(v);
    assertEquals("Verification must be successful", i.status, 0);
    assertEquals("Signature must exist", i.info.signatures.size(), 1);
    assertEquals("Cert must be trusted", ((i.info.signatures.get(0)).certs.get(0)).trusted, true);
    assertEquals("Cert must be verified", ((i.info.signatures.get(0)).certs.get(0)).verified, true);
  }


}
