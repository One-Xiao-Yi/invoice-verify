package com.xiao.yi.invoice.verify.ofd;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.lang.UUID;
import cn.hutool.core.util.ZipUtil;
import cn.hutool.crypto.ECKeyUtil;
import cn.hutool.crypto.asymmetric.SM2;
import cn.hutool.crypto.digest.SM3;
import org.bouncycastle.asn1.*;
import cn.hutool.core.io.IoUtil;
import org.bouncycastle.asn1.x509.Certificate;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Objects;

/**
 * @author xiaoyi
 * @since 2023/3/21
 */
public class OFDVerifier {

    public static boolean verify(InputStream inputStream) {
        String tmpPath = FileUtil.getTmpDir().getPath();
        String ofdUnzipDirPath = tmpPath + File.separator + "ofd-unzip" + File.separator + UUID.fastUUID().toString();
        File ofdUnzipDir = FileUtil.mkdir(ofdUnzipDirPath);
        File file = ZipUtil.unzip(inputStream, ofdUnzipDir, Charset.defaultCharset());

        File doc0 = searchChildFile(file, "Doc_0");
        if (null == doc0 || !doc0.isDirectory()) {
            return false;
        }

        File signs = searchChildFile(doc0, "Signs");
        if (null == signs || !signs.isDirectory()) {
            return false;
        }

        File sign0 = searchChildFile(signs, "Sign_0");
        if (null == sign0 || !sign0.isDirectory()) {
            return false;
        }

        File signedValue = searchChildFile(sign0, "SignedValue.dat");
        if (null == signedValue || !signedValue.isFile()) {
            return false;
        }

        File signXml = searchChildFile(sign0, "Signature.xml");
        if (null == signXml || !signXml.isFile()) {
            return false;
        }

        byte[] bytes = null;
        try (InputStream signedInputStream = Files.newInputStream(signedValue.toPath())){
            bytes = IoUtil.readBytes(signedInputStream);
        } catch (IOException e) {
            throw new RuntimeException("读取加密文件失败", e);
        }


        try (ASN1InputStream asn1InputStream = new ASN1InputStream(bytes);){
            ASN1Primitive asn1Primitive = asn1InputStream.readObject();
            DLSequence root = (DLSequence) asn1Primitive;

            DLSequence signInfo = (DLSequence) root.getObjectAt(0);
            DLSequence seal = (DLSequence) signInfo.getObjectAt(1);
            DLSequence sealInfo = (DLSequence) seal.getObjectAt(0);
            Certificate cert = Certificate.getInstance(((DEROctetString) seal.getObjectAt(1)).getOctets());
            if (!verify(sealInfo, cert.getSubjectPublicKeyInfo().getPublicKeyData().getOctets(), ((DERBitString) seal.getObjectAt(3)).getOctets())) {
                return false;
            }

            DEROctetString signCertOctet = (DEROctetString) root.getObjectAt(1);
            Certificate signCert = Certificate.getInstance(signCertOctet.getOctets());
            if (!verify(signInfo, signCert.getSubjectPublicKeyInfo().getPublicKeyData().getOctets(), ((DERBitString) root.getObjectAt(3)).getOctets())) {
                return false;
            }

            DERBitString signed = (DERBitString) signInfo.getObjectAt(3);

            try (InputStream signXmlInputStream = Files.newInputStream(signXml.toPath())){
                byte[] digest = SM3.create().digest(signXmlInputStream);
                return Arrays.equals(digest, signed.getOctets());
            }
        } catch (IOException e) {
            throw new RuntimeException("读取OFD文件失败", e);
        }
    }

    private static boolean verify(DLSequence dlSequence, byte[] publicKey, byte[] sign) {
        ASN1OutputStream outputStream = null;
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            outputStream = ASN1OutputStream.create(byteArrayOutputStream);
            outputStream.writeObject(dlSequence);
            outputStream.flush();
            byte[] sealData = byteArrayOutputStream.toByteArray();
            SM2 sm2 = new SM2(null, ECKeyUtil.toSm2PublicParams(publicKey));
            return sm2.verify(sealData, sign);
        } catch (Exception e) {
            throw new RuntimeException("签名验证失败", e);
        } finally {
            if (null != outputStream) {
                try {
                    outputStream.close();
                } catch (IOException e) {
                    // ignore
                }
            }
        }
    }

    private static File searchChildFile(File dir, String childName) {
        File[] files = dir.listFiles();

        if (null == files || files.length == 0) {
            return null;
        }

        File doc0 = null;

        for (File item : files) {
            if (item.getName().equals(childName)) {
                return item;
            }
        }
        return null;
    }

}
