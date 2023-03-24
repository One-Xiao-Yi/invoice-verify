package com.xiao.yi.invoice.verify.pdf;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

/**
 * @author xiaoyi
 * @since 2023/3/21
 */
public class PDFVerifier {

    public static boolean verify(InputStream inputStream) {
        byte[] bytes = null;
        try {
            int available = inputStream.available();
            bytes = new byte[available];
            inputStream.read(bytes, 0, available);
        } catch (IOException e) {
            throw new RuntimeException("文件读取失败", e);
        }
        PDDocument document = null;
        try {
            document = PDDocument.load(bytes);
        } catch (IOException e) {
            return false;
        }

        try {
            List<PDSignature> signs = null;

            try {
                signs = document.getSignatureDictionaries();
            } catch (IOException e) {
                return false;
            }

            if (null == signs || signs.size() == 0) {
                return false;
            }

            PDSignature sign = signs.get(0);
            byte[] contents = sign.getContents();
            byte[] signedContent = new byte[0];
            try {
                signedContent = sign.getSignedContent(bytes);
            } catch (IOException e) {
                throw new RuntimeException("获取加密区失败", e);
            }
            return verifyPKCS7(signedContent, contents, sign);
        } finally {
            try {
                document.close();
            } catch (IOException e) {
                // ignore
            }
        }
    }

    private static boolean verifyPKCS7(byte[] byteArray, byte[] contents, PDSignature sig) {
        CMSProcessable signedContent = new CMSProcessableByteArray(byteArray);
        CMSSignedData signedData = null;
        try {
            signedData = new CMSSignedData(signedContent, contents);
        } catch (CMSException e) {
            throw new RuntimeException("格式转化失败", e);
        }
        Store<X509CertificateHolder> certificatesStore = signedData.getCertificates();
        if (certificatesStore.getMatches(null).isEmpty()) {
            return false;
        }
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        if (signers.isEmpty()) {
            return false;
        }
        SignerInformation signerInformation = signers.iterator().next();
        Collection<X509CertificateHolder> matches = certificatesStore.getMatches(signerInformation.getSID());
        if (matches.isEmpty()) {
            return false;
        }
        X509CertificateHolder certificateHolder = matches.iterator().next();
        X509Certificate certFromSignedData = null;
        try {
            certFromSignedData = new JcaX509CertificateConverter().getCertificate(certificateHolder);
        } catch (CertificateException e) {
            throw new RuntimeException("获取证书失败", e);
        }

        try {
            if (sig.getSignDate() != null) {
                certFromSignedData.checkValidity(sig.getSignDate().getTime());
            } else {
                return false;
            }
        } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
            return false;
        }

        if (signerInformation.getSignedAttributes() != null) {
            Attribute signingTime = signerInformation.getSignedAttributes().get(CMSAttributes.signingTime);
            if (signingTime != null) {
                Time timeInstance = Time.getInstance(signingTime.getAttrValues().getObjectAt(0));
                try {
                    certFromSignedData.checkValidity(timeInstance.getDate());
                } catch (CertificateExpiredException | CertificateNotYetValidException ex) {
                    return false;
                }
            }
        }
        try {
            return signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().
                    setProvider(SecurityProvider.getProvider()).build(certFromSignedData));
        } catch (CMSVerifierCertificateNotValidException e) {
            return false;
        } catch (CMSException | OperatorCreationException | IOException e) {
            throw new RuntimeException("签名校验失败", e);
        }
    }

}
