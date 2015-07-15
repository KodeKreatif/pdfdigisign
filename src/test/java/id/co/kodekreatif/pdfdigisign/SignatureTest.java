package id.co.kodekreatif.pdfdigisign;
import id.co.kodekreatif.pdfdigisign.Signature;

import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.assertEquals;

class SignStore {
  public KeyStore store = null;
  public PrivateKey privateKey = null;
  public Certificate[] chain = {};
  char[] password = new String("test").toCharArray();
  final Date startDate;

  public SignStore(Date start) {
    startDate = start;
    String certAlias = new String("cert");
    try {
      store = KeyStore.getInstance(KeyStore.getDefaultType());
      store.load(null, null);
      generatePrivateKey();
    } catch(Exception e) {
      e.printStackTrace();
    }
  }
  
  public SignStore() {
    this(new Date());
  }

  void generatePrivateKey() {
    String alias = new String("private");
    try {
      CertAndKeyGen gen = new CertAndKeyGen("RSA","SHA1WithRSA");
      gen.generate(1024);
      privateKey = gen.getPrivateKey();
      X509Certificate cert=gen.getSelfCertificate(new X500Name("CN=ROOT"), startDate, (long)30*24*3600);

      chain = new X509Certificate[1];
      chain[0] = cert;

      store.setKeyEntry(alias, privateKey, password, chain);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  void setTrusted() {
    try {
      store.setCertificateEntry("cert", chain[0]);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

public class SignatureTest {

  @Test
  public void testOneSignature() {
    
    SignStore store = new SignStore();
    Signature signature = new Signature(store.chain, store.privateKey);
    try {
      signature.signWithAlias("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/no-signature.pdf", "/tmp", "alias", "name", "location", "reason");
      Verificator v = new Verificator("/tmp/no-signature.pdf.signed.pdf");
      PDFDocumentInfo i = v.validate();
      assertEquals("Signature must exist", i.signatures.size(), 1);
      assertEquals("Cert must be trusted", ((i.signatures.get(0)).certs.get(0)).trusted, false);
      assertEquals("Cert must be verified", ((i.signatures.get(0)).certs.get(0)).verified, true);

    } catch(Exception e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testOneTrustedSignature() {
    
    SignStore store = new SignStore();
    store.setTrusted();
    Signature signature = new Signature(store.chain, store.privateKey);
    try {
      signature.signWithAlias("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/no-signature.pdf", "/tmp", "alias", "name", "location", "reason");
      Verificator v = new Verificator("/tmp/no-signature.pdf.signed.pdf");
      v.setKeyStore(store.store);
      PDFDocumentInfo i = v.validate();
      assertEquals("Signature must exist", i.signatures.size(), 1);
      assertEquals("Cert must be trusted", ((i.signatures.get(0)).certs.get(0)).trusted, true);
      assertEquals("Cert must be verified", ((i.signatures.get(0)).certs.get(0)).verified, true);

    } catch(Exception e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testExpiredSignature() {
    Date startDate = new Date();
    startDate.setYear(startDate.getYear() - 2);
    SignStore store = new SignStore(startDate);
    Signature signature = new Signature(store.chain, store.privateKey);
    try {
      signature.signWithAlias("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/no-signature.pdf", "/tmp", "alias", "name", "location", "reason");
      Verificator v = new Verificator("/tmp/no-signature.pdf.signed.pdf");
      PDFDocumentInfo i = v.validate();
      assertEquals("Signature must exist", i.signatures.size(), 1);
      assertEquals("Cert must be trusted", ((i.signatures.get(0)).certs.get(0)).trusted, false);
      assertEquals("Cert must be verified", ((i.signatures.get(0)).certs.get(0)).verified, true);
      assertEquals("Cert must not be valid", ((i.signatures.get(0)).certs.get(0)).valid, false);
      assertEquals("Cert must not be valid", ((i.signatures.get(0)).certs.get(0)).problems.get(0), "expired");

    } catch(Exception e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testNotYetValidSignature() {
    Date startDate = new Date();
    startDate.setYear(startDate.getYear() + 2);
    SignStore store = new SignStore(startDate);
    Signature signature = new Signature(store.chain, store.privateKey);
    try {
      signature.signWithAlias("./src/test/java/id/co/kodekreatif/pdfdigisign/assets/no-signature.pdf", "/tmp", "alias", "name", "location", "reason");
      Verificator v = new Verificator("/tmp/no-signature.pdf.signed.pdf");
      PDFDocumentInfo i = v.validate();
      assertEquals("Signature must exist", i.signatures.size(), 1);
      assertEquals("Cert must be trusted", ((i.signatures.get(0)).certs.get(0)).trusted, false);
      assertEquals("Cert must be verified", ((i.signatures.get(0)).certs.get(0)).verified, true);
      assertEquals("Cert must not be valid", ((i.signatures.get(0)).certs.get(0)).valid, false);
      assertEquals("Cert must not be valid", ((i.signatures.get(0)).certs.get(0)).problems.get(0), "not-yet-valid");

    } catch(Exception e) {
      e.printStackTrace();
    }
  }


}
