package org.bouncycastle.jcajce.provider.asymmetric.x509;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Exceptions;
import org.bouncycastle.util.Strings;

class X509SignatureUtil
{
    private static final Map<ASN1ObjectIdentifier, String> algNames = new HashMap<ASN1ObjectIdentifier, String>();

    static
    {
        algNames.put(EdECObjectIdentifiers.id_Ed25519, "Ed25519");
        algNames.put(EdECObjectIdentifiers.id_Ed448, "Ed448");
        algNames.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1withDSA");
        algNames.put(X9ObjectIdentifiers.id_dsa_with_sha1, "SHA1withDSA");
    }

    static byte[] getExtensionValue(Extensions extensions, String oid) 
    {
        if (oid != null)
        {
            ASN1ObjectIdentifier asn1Oid = ASN1ObjectIdentifier.tryFromID(oid);
            if (asn1Oid != null)
            {
                ASN1OctetString extValue = Extensions.getExtensionValue(extensions, asn1Oid);
                if (null != extValue)
                {
                    try
                    {
                        return extValue.getEncoded();
                    }
                    catch (Exception e)
                    {
                        throw Exceptions.illegalStateException("error parsing " + e.getMessage(), e);
                    }
                }
            }
        }
        return null;
    }

    private static boolean isAbsentOrEmptyParameters(ASN1Encodable parameters)
    {
        return parameters == null || DERNull.INSTANCE.equals(parameters);
    }

    static void setSignatureParameters(Signature signature, ASN1Encodable params)
        throws NoSuchAlgorithmException, SignatureException, InvalidKeyException
    {
        if (!isAbsentOrEmptyParameters(params))
        {
            String sigAlgName = signature.getAlgorithm();

            String sigParamsAlg;
            if (sigAlgName.indexOf("MGF1") > 0)
            {
                sigParamsAlg = "PSS";
            }
            else
            {
                sigParamsAlg = Strings.toUpperCase(sigAlgName);
            }

            try
            {
                AlgorithmParameters sigParams = AlgorithmParameters.getInstance(sigParamsAlg);

                sigParams.init(params.toASN1Primitive().getEncoded());
            }
            catch (IOException e)
            {
                throw new SignatureException("IOException decoding parameters: " + e.getMessage());
            }
        }
    }

    static String getSignatureName(AlgorithmIdentifier sigAlgId) 
    {
        ASN1ObjectIdentifier sigAlgOid = sigAlgId.getAlgorithm();
        ASN1Encodable params = sigAlgId.getParameters();

        if (!isAbsentOrEmptyParameters(params))
        {
            if (PKCSObjectIdentifiers.id_RSASSA_PSS.equals(sigAlgOid))
            {
                RSASSAPSSparams rsaParams = RSASSAPSSparams.getInstance(params);

                return getDigestAlgName(rsaParams.getHashAlgorithm().getAlgorithm()) + "WITHRSAANDMGF1";
            }
            if (X9ObjectIdentifiers.ecdsa_with_SHA2.equals(sigAlgOid))
            {
                AlgorithmIdentifier ecDsaParams = AlgorithmIdentifier.getInstance(params);

                return getDigestAlgName(ecDsaParams.getAlgorithm()) + "WITHECDSA";
            }
        }

        // deal with the "weird" ones.
        String algName = (String)algNames.get(sigAlgOid);
        if (algName != null)
        {
            return algName;
        }

        return findAlgName(sigAlgOid);
    }

    /**
     * Return the digest algorithm using one of the standard JCA string
     * representations rather the the algorithm identifier (if possible).
     */
    private static String getDigestAlgName(
        ASN1ObjectIdentifier digestAlgOID)
    {
        String name = MessageDigestUtils.getDigestName(digestAlgOID);

        int dIndex = name.indexOf('-');
        if (dIndex > 0 && !name.startsWith("SHA3"))
        {
            return name.substring(0, dIndex) + name.substring(dIndex + 1);
        }

        return MessageDigestUtils.getDigestName(digestAlgOID);
    }

    private static String findAlgName(ASN1ObjectIdentifier algOid)
    {
        Provider prov = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

        if (prov != null)
        {
            String algName = lookupAlg(prov, algOid);
            if (algName != null)
            {
                return algName;
            }
        }

        Provider[] provs = Security.getProviders();

        for (int i = 0; i != provs.length; i++)
        {
            if (prov != provs[i])
            {
                String algName = lookupAlg(provs[i], algOid);
                if (algName != null)
                {
                    return algName;
                }
            }
        }

        return algOid.getId();
    }

    private static String lookupAlg(Provider prov, ASN1ObjectIdentifier algOid)
    {
        String algName = prov.getProperty("Alg.Alias.Signature." + algOid);

        if (algName != null)
        {
            return algName;
        }

        algName = prov.getProperty("Alg.Alias.Signature.OID." + algOid);

        if (algName != null)
        {
            return algName;
        }

        return null;
    }
}
