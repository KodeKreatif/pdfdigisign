package id.co.kodekreatif.pdfdigisign;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.InterruptedException;

import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateRevokedException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.TrustAnchor;
import java.security.cert.PKIXParameters;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXCertPathValidatorResult;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Vector;
import java.util.HashSet;
import java.util.Set;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

/**
 * Verifies digital signatures (if any) embedded in a PDF file
 */
public class Verificator {

  private PDFDocumentInfo doc = new PDFDocumentInfo();

  private PrivateKey privKey;
  private Certificate cert;
  private String path;
  private KeyStore keyStore = null;

  // http://stackoverflow.com/a/9855338
  private static String bytesToHex(byte[] bytes) {
    final char[] hexArray = "0123456789ABCDEF".toCharArray();
    char[] hexChars = new char[bytes.length * 2];
    for ( int j = 0; j < bytes.length; j++ ) {
      int v = bytes[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  /**
   *
   * Checks the revocation status of a certificate
   *
   * @param caCert The CA cert to be checked
   * @param cert The cert to be checked
   * @param certInfo CertInfo structure which will be populated
   * @return the populated @CertInfo structure
   **/
  public static CertInfo checkRevocation(final X509Certificate caCert, final X509Certificate cert, CertInfo certInfo) {
    System.setProperty("com.sun.security.enableCRLDP", "true");
    try {
      Vector<X509Certificate> certs = new Vector<X509Certificate>();
      certs.add(cert);

      CertificateFactory factory = CertificateFactory.getInstance("X509");
      CertPath path = factory.generateCertPath(certs);

      TrustAnchor anchor = new TrustAnchor(caCert, null);
      Set<TrustAnchor> trusted = new HashSet<TrustAnchor>();
      trusted.add(anchor);

      PKIXParameters params = new PKIXParameters(trusted);
      CertPathValidator validator = CertPathValidator.getInstance("PKIX");
      try {
        PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(path, params);
      } catch (Exception e) {
        if (e.getCause() != null  && e.getCause().getClass().getName().equals("java.security.cert.CertificateRevokedException")) {
          CertificateRevokedException r = (CertificateRevokedException) e.getCause();

          certInfo.revoked = true;
          certInfo.revocationPrincipal = r.getAuthorityName().toString();
          certInfo.revocationDate = r.getRevocationDate();
          certInfo.revocationReason = r.getRevocationReason().toString();
        } else {
          certInfo.verified = false;
          certInfo.problems.add("Revocation state could not be determined.");
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    }

    return certInfo;
  }

  /**
   *
   * Checks keystore for a specific cert record, and populate it in a <CertInfo> structure
   *
   * @param keyStore The KeyStore to use
   * @param cert The cert to be checked
   * @param certInfo CertInfo structure which will be populated
   * @return the populated CertInfo structure
   **/
  public static CertInfo checkKeyStore(KeyStore keyStore, final X509Certificate cert, CertInfo certInfo) throws KeyStoreException, IOException, NoSuchAlgorithmException, FileNotFoundException, CertificateException{

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(keyStore);
    X509TrustManager xtm = (X509TrustManager) tmf.getTrustManagers()[0];
    String issuer = cert.getIssuerX500Principal().getName();
    X509Certificate caCert = null;

    for (X509Certificate storeCert : xtm.getAcceptedIssuers()) {
      String storePrincipal = storeCert.getSubjectX500Principal().getName();

      if (storePrincipal.equals(issuer)) {
        try {
          cert.verify(storeCert.getPublicKey());
          certInfo.trusted = true;
          caCert = storeCert;
        } catch (Exception e) {
          certInfo.trusted = false;
          certInfo.problems.add(e.getMessage());
        }
        finally {
          break;
        }
      }
    }

    if (caCert == null) {
      certInfo.trusted = false;
    } else {
      certInfo = checkRevocation(caCert, cert, certInfo);
    }

    return certInfo;
  }

  private void getSignatureInfo(final COSDictionary sigRecord) throws KeyStoreException, IOException, NoSuchAlgorithmException {

    String name = sigRecord.getString(COSName.NAME, "Unknown");
    String location = sigRecord.getString(COSName.LOCATION, "Unknown");
    String reason = sigRecord.getString(COSName.REASON, "Unknown");
    String contactInfo = sigRecord.getString(COSName.CONTACT_INFO, "Unknown");
    String modified = sigRecord.getString(COSName.M);

    SignatureInfo info = new SignatureInfo();
    info.name = name;
    info.modified = modified;
    info.location = location;
    info.reason = reason;
    info.contactInfo = contactInfo;

    COSName subFilter = (COSName) sigRecord.getDictionaryObject(COSName.SUB_FILTER);

    if (subFilter == null) {
      return;
    }

    try {
      COSString certString = (COSString) sigRecord.getDictionaryObject(COSName.CONTENTS);
      byte[] certData = certString.getBytes();
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      ByteArrayInputStream certStream = new ByteArrayInputStream(certData);
      final CertPath certPath = factory.generateCertPath(certStream, "PKCS7");
      Collection<? extends Certificate> certs = certPath.getCertificates();

      for (Certificate c: certs) {
        X509Certificate x509 = (X509Certificate) c;
        CertInfo certInfo = new CertInfo();

        certInfo.serialNumber = x509.getSerialNumber().toString();
        certInfo.signature = bytesToHex(x509.getSignature());
        certInfo.issuer = x509.getIssuerX500Principal().toString();
        certInfo.subject = x509.getSubjectX500Principal().toString();

        try {
          if (certInfo.issuer.equals(certInfo.subject)) {
            certInfo.selfSigned = true;
          } else {
            certInfo.selfSigned = false;
          }

          certInfo.verified = true;
          certInfo = checkKeyStore(keyStore, x509, certInfo);
        } catch (Exception e) {
          certInfo.verified = false;
          certInfo.problems.add(e.getMessage());
        }

        certInfo.notBefore = x509.getNotBefore();
        certInfo.notAfter = x509.getNotAfter();

        try {
          x509.checkValidity();
          certInfo.valid = true;
        } catch (CertificateExpiredException e) {
          certInfo.problems.add("expired");
          certInfo.valid = false;
        } catch (CertificateNotYetValidException e) {
          certInfo.problems.add("not-yet-valid");
          certInfo.valid = false;
        }
        info.certs.add(certInfo);
      }
    } catch (CertificateException e) {
      e.printStackTrace();
    }
    doc.signatures.add(info);
  }

  /**
   * Constructor
   *
   * @param path Path pointing to a PDF file to be validated
   **/
  public Verificator(final String path) {
    this.path = path;
  }

  /**
   * Sets a custom KeyStore
   */
  public void setKeyStore(final KeyStore keyStore) {
    this.keyStore = keyStore;
  }

  /**
   * Validates the PDF file specified in the constructor
   * @return PDFDocumentInfo structure
   **/
  public PDFDocumentInfo validate() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
    String infoString = null;
    PDDocument document = null;
    try {
      document = PDDocument.load(new File(path));

      COSDictionary trailer = document.getDocument().getTrailer();
      COSDictionary root = (COSDictionary) trailer.getDictionaryObject(COSName.ROOT);
      COSDictionary acroForm = (COSDictionary) root.getDictionaryObject(COSName.ACRO_FORM);
      if (acroForm == null) {
        return doc;
      }
      COSArray fields = (COSArray) acroForm.getDictionaryObject(COSName.FIELDS);

      for (int i = 0; i < fields.size(); i ++) {
        COSDictionary field = (COSDictionary) fields.getObject(i);

        COSName type = field.getCOSName(COSName.FT);
        if (COSName.SIG.equals(type)) {
          COSDictionary sig = (COSDictionary) field.getDictionaryObject(COSName.V);
          if (sig != null) {
            getSignatureInfo(sig);
          }
        }
      }
    }
    finally {
      if (document != null) {
        document.close();
      }
    }
    return doc;
  }
}
