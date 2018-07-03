package com.sample;

import javax.crypto.interfaces.DHPublicKey;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

public class Main {

        public static void main(String[] args) {
                try {
                        // Base64エンコードされた証明書
                        String certificate = "-----BEGIN CERTIFICATE-----\n"
                                + "MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh\n"
                                + "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
                                + "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\n"
                                + "QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT\n"
                                + "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n"
                                + "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG\n"
                                + "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB\n"
                                + "CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97\n"
                                + "nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt\n"
                                + "43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P\n"
                                + "T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4\n"
                                + "gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO\n"
                                + "BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR\n"
                                + "TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw\n"
                                + "DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr\n"
                                + "hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg\n"
                                + "06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF\n"
                                + "PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls\n"
                                + "YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk\n"
                                + "CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=\n"
                                + "-----END CERTIFICATE-----";

                        // X509Certificate に変換
                        CertificateFactory factory = CertificateFactory.getInstance("X.509");
                        InputStream stream = new ByteArrayInputStream(
                                certificate.getBytes(StandardCharsets.UTF_8));
                        X509Certificate cert = (X509Certificate) factory
                                .generateCertificate(stream);

                        // コモンネーム等を調べる
                        String issuerNames = cert.getSubjectX500Principal().getName();
                        Map<String, String> nameMap = Arrays.stream(issuerNames.split(","))
                                .map(x -> x.split("="))
                                .collect(Collectors.toMap(x -> x[0], x -> x[1]));
                        nameMap.forEach((key, value) -> System.out.println(key + ":" + value));

                        // 期限を調べる
                        Date notBefore = cert.getNotBefore();
                        System.out.println("notBefore = [" + notBefore + "]");
                        Date notAfter = cert.getNotAfter();
                        System.out.println("notAfter = [" + notAfter + "]");

                        // 公開鍵の鍵長を調べる
                        // https://docs.oracle.com/javase/jp/6/technotes/guides/security/StandardNames.html
                        // KeyFactory アルゴリズム 参照
                        String algorithm = cert.getPublicKey().getAlgorithm();
                        switch (algorithm) {
                                case "RSA": {
                                        RSAPublicKey key = (RSAPublicKey) cert.getPublicKey();
                                        System.out.println(
                                                "RSA: " + key.getModulus().bitLength() + " bit");
                                        break;
                                }
                                case "DiffieHellman": {
                                        DHPublicKey key = (DHPublicKey) cert.getPublicKey();
                                        System.out.println(
                                                "DiffieHellman: " + key.getY().bitLength()
                                                        + " bit");
                                        break;
                                }
                                case "DSA": {
                                        DSAPublicKey key = (DSAPublicKey) cert.getPublicKey();
                                        System.out
                                                .println("DSA: " + key.getY().bitLength() + " bit");
                                        break;
                                }
                                case "EC": {
                                        ECPublicKey key = (ECPublicKey) cert.getPublicKey();
                                        System.out.println(
                                                "EC: " + key.getW().getAffineX().bitLength()
                                                        + " bit");
                                        System.out.println(
                                                "EC: " + key.getW().getAffineY().bitLength()
                                                        + " bit");
                                        break;
                                }
                        }

                } catch (CertificateException e) {
                        e.printStackTrace();
                }
        }
}
