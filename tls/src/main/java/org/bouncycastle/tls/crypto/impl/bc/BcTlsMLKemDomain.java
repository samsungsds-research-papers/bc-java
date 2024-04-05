package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsKEMConfig;
import org.bouncycastle.tls.crypto.TlsKEMDomain;
import org.bouncycastle.tls.crypto.TlsSecret;

public class BcTlsMLKemDomain implements TlsKEMDomain
{
    public static KyberParameters getKyberParameters(TlsKEMConfig kemConfig)
    {
        switch (kemConfig.getKEMNamedGroup())
        {
        case NamedGroup.mlkem512:
            return KyberParameters.kyber512;
        case NamedGroup.mlkem768:
            return KyberParameters.kyber768;
        case NamedGroup.mlkem1024:
            return KyberParameters.kyber1024;
        default:
            return null;
        }
    }

    protected final BcTlsCrypto crypto;
    protected final TlsKEMConfig kemConfig;
    protected final KyberParameters kyberParameters;

    public TlsKEMConfig getTlsKEMConfig()
    {
        return kemConfig;
    }

    public BcTlsMLKemDomain(BcTlsCrypto crypto, TlsKEMConfig kemConfig)
    {
        this.crypto = crypto;
        this.kemConfig = kemConfig;
        this.kyberParameters = getKyberParameters(kemConfig);
    }

    public TlsAgreement createKEM()
    {
        return new BcTlsMLKem(this);
    }

    public KyberPublicKeyParameters decodePublicKey(byte[] encoding)
    {
        return new KyberPublicKeyParameters(kyberParameters, encoding);
    }

    public byte[] encodePublicKey(KyberPublicKeyParameters kyberPublicKeyParameters)
    {
        return kyberPublicKeyParameters.getEncoded();
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        KyberKeyPairGenerator keyPairGenerator = new KyberKeyPairGenerator();
        keyPairGenerator.init(new KyberKeyGenerationParameters(crypto.getSecureRandom(), kyberParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public TlsSecret adoptLocalSecret(byte[] secret)
    {
        return crypto.adoptLocalSecret(secret);
    }

    public SecretWithEncapsulation encapsulate(KyberPublicKeyParameters peerPublicKey)
    {
        KyberKEMGenerator kemGenerator = new KyberKEMGenerator(crypto.getSecureRandom());
        return kemGenerator.generateEncapsulated(peerPublicKey);
    }

    public byte[] decapsulate(KyberPrivateKeyParameters kyberPrivateKeyParameters, byte[] cipherText)
    {
        KyberKEMExtractor kemExtract = new KyberKEMExtractor(kyberPrivateKeyParameters);
        byte[] secret = kemExtract.extractSecret(cipherText);
        return secret;
    }
}
