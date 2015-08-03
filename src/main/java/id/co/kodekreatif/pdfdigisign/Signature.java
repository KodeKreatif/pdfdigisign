package id.co.kodekreatif.pdfdigisign;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.InterruptedException;
import java.lang.StringBuilder;

import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.List;

import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.cert.X509CertificateHolder;

import org.spongycastle.cert.jcajce.JcaCertStore;
import org.spongycastle.cms.CMSSignedData;
import org.spongycastle.cms.CMSSignedDataGenerator;
import org.spongycastle.cms.CMSSignedGenerator;
import org.spongycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.spongycastle.util.Store;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;

/**
 * Signs a PDF file with a digital signature
 */
public class Signature implements SignatureInterface {

  private static BouncyCastleProvider provider = new BouncyCastleProvider();

  private PrivateKey privKey;
  Certificate[] chain;
  InputStream imageStream = null;
  int visualPage = -1;
  float visualX, visualY;
  float visualHeight, visualWidth;

  /**
   * Constructor
   *
   * @param chain The certificate chain used to sign the PDF file
   * @param key The PrivateKey used to sign the PDF file
   */
  public Signature(final Certificate[] chain, PrivateKey key) {
    this.chain = chain;
    privKey = key;
  }

  /**
   * Set visual presentation of the signature
   *
   * @param stream The InputStream of an image file (ie. a PNG file stream)
   * @param page The page the presentation would be embedded in the file
   * @param x The location of the presentation within the page in x-axis
   * @param y The location of the presentation within the page in y-axis
   * @param height The height of the presentation
   * @param width The width of the presentation
   */
  public void setVisual(InputStream stream, int page, float x, float y, float width, float height) {
    imageStream = stream;
    visualPage = page;
    visualX = x;
    visualY = y;
    visualHeight = height;
    visualWidth = width;
  }

  /**
   * Signs the PDF file
   *
   * @param path The path to the PDF file
   * @param outputPath The directory where the output file would be saved
   * @param name The name of the person making the signature
   * @param location The place/location where the signing took place
   * @param reason The reason why the file was signed
   */
  public void sign(final String path, final String outputPath, final String name, final String location, final String reason) throws IOException, InterruptedException 
  {
    File document = new File(path);

    File outputDocument = new File(outputPath + "/" + document.getName() + ".signed.pdf");
    FileOutputStream fos = new FileOutputStream(outputDocument);

    PDDocument doc = PDDocument.load(document);

    PDSignature signature = new PDSignature();
    signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); 
    signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
    signature.setName(name);
    signature.setLocation(location);
    signature.setReason(reason);
    signature.setSignDate(Calendar.getInstance());

    if (imageStream != null) {
      PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner(doc, imageStream, visualPage);
      visibleSig
        .xAxis(visualX)
        .yAxis(visualY)
        .height(visualHeight)
        .width(visualWidth)
        .signatureFieldName("signature");

      PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();

      signatureProperties
        .preferredSize(0)
        .page(visualPage)
        .visualSignEnabled(true)
        .setPdVisibleSignature(visibleSig)
        .buildSignature();
      
      SignatureOptions options = null;
      try {
        options = new SignatureOptions();
        options.setVisualSignature(signatureProperties);
        options.setPage(visualPage - 1);
        doc.addSignature(signature, this, options);
        doc.saveIncremental(fos);
      }  
      finally
      {
        doc.close();
      }
    } else {
      doc.addSignature(signature, this);
      doc.saveIncremental(fos);
      doc.close();
    }
  }


  // Internal function called by PDFBox during signing
  @Override
  public byte[] sign(InputStream content) throws IOException 
  {
    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    SignatureData input = new SignatureData(content);
    List<Certificate> certs = new ArrayList<Certificate>();
    for (int i = 0; i < chain.length; i ++) {
      certs.add(chain[i]);
    }

    try
    {
      Store certStore = new JcaCertStore(certs);

      Certificate cert = chain[0];
      org.spongycastle.asn1.x509.Certificate x509Cert =
        org.spongycastle.asn1.x509.Certificate.getInstance(ASN1Primitive.fromByteArray(cert.getEncoded()));

      ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").build(privKey);
      gen.addSignerInfoGenerator(
               new JcaSignerInfoGeneratorBuilder(
               new JcaDigestCalculatorProviderBuilder().build())
               .build(sha256Signer, new X509CertificateHolder(x509Cert)));

      gen.addCertificates(certStore);
      CMSSignedData signedData = gen.generate(input, false);
      return signedData.getEncoded();
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    throw new RuntimeException("Signing error, look at the stack trace");
  }
}


