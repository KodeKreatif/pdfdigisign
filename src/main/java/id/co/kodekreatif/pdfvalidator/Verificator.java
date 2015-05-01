package id.co.kodekreatif.pdfvalidator;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.lang.InterruptedException;
import java.lang.StringBuilder;

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
import java.util.Enumeration;
import java.util.List;
import java.util.TimeZone;
import java.util.Vector;
import java.util.HashSet;
import java.util.Set;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;


import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

public class Verificator {

  private PDFDocumentInfo info = new PDFDocumentInfo();

  private PrivateKey privKey;
  private Certificate cert;
  private String path;

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
          TimeZone tz = TimeZone.getTimeZone("UTC");
          DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mmZ");
          df.setTimeZone(tz);

          certInfo.revoked = true;
          certInfo.revocationPrincipal = r.getAuthorityName().toString();
          certInfo.revocationDate = r.getRevocationDate();
          certInfo.revocationReason = r.getRevocationReason().toString();
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    }

    return certInfo;
  }

  public static CertInfo checkKeyStore(final X509Certificate cert, CertInfo certInfo) throws KeyStoreException, IOException, NoSuchAlgorithmException, FileNotFoundException, CertificateException{

    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init((KeyStore) null);
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
          certInfo.verificationFailure = e.getMessage();
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

  private void getInfoFromCert(final COSDictionary cert) throws KeyStoreException, IOException, NoSuchAlgorithmException {

    String name = cert.getString(COSName.NAME, "Unknown");
    String location = cert.getString(COSName.LOCATION, "Unknown");
    String reason = cert.getString(COSName.REASON, "Unknown");
    String contactInfo = cert.getString(COSName.CONTACT_INFO, "Unknown");
    String modified = cert.getString(COSName.M);

    info.hasSignature = true;
    info.name = name;
    info.modified = modified;
    info.location = location;
    info.reason = reason;
    info.contactInfo = contactInfo;

    COSName subFilter = (COSName) cert.getDictionaryObject(COSName.SUB_FILTER);

    if (subFilter == null) {
      return;
    }

    try {
      COSString certString = (COSString) cert.getDictionaryObject(COSName.CONTENTS);
      byte[] certData = certString.getBytes();
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      ByteArrayInputStream certStream = new ByteArrayInputStream(certData);
      final CertPath certPath = factory.generateCertPath(certStream, "PKCS7");
      Collection<? extends Certificate> certs = certPath.getCertificates();

      StringBuilder certJSON = new StringBuilder();

      TimeZone tz = TimeZone.getTimeZone("UTC");
      DateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mmZ");
      df.setTimeZone(tz);

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

          certInfo = checkKeyStore(x509, certInfo);
          certInfo.verified = true;
        } catch (Exception e) {
          certInfo.verified = false;
          certInfo.verificationFailure = e.getMessage();
        }

        certInfo.notBefore = x509.getNotBefore();
        certInfo.notAfter = x509.getNotAfter();

        try {
          x509.checkValidity();
          certInfo.state = "valid";
        } catch (CertificateExpiredException e) {
          certInfo.state = "expired";
        } catch (CertificateNotYetValidException e) {
          certInfo.state = "notYet";
        }
        info.certs.add(certInfo);
      }
    } catch (CertificateException e) {
      e.printStackTrace();
    }

  }

  public Verificator(final String path) {
    this.path = path;
  }

  public PDFDocumentInfo validate() throws IOException, CertificateException, KeyStoreException, NoSuchAlgorithmException {
    String infoString = null;
    PDDocument document = null;
    try {
      document = PDDocument.load(new File(path));

      COSDictionary trailer = document.getDocument().getTrailer();
      COSDictionary root = (COSDictionary) trailer.getDictionaryObject(COSName.ROOT);
      COSDictionary acroForm = (COSDictionary) root.getDictionaryObject(COSName.ACRO_FORM);
      if (acroForm == null) {
        return info;
      }
      COSArray fields = (COSArray) acroForm.getDictionaryObject(COSName.FIELDS);

      boolean certFound = false;
      for (int i = 0; i < fields.size(); i ++) {
        COSDictionary field = (COSDictionary) fields.getObject(i);

        COSName type = field.getCOSName(COSName.FT);
        if (COSName.SIG.equals(type)) {
          COSDictionary cert = (COSDictionary) field.getDictionaryObject(COSName.V);
          if (cert != null) {
            getInfoFromCert(cert);
            certFound = true;
          }
        }

      }

    }
    finally {
      if (document != null) {
        document.close();
      }
    }
    return info;
  }

}


