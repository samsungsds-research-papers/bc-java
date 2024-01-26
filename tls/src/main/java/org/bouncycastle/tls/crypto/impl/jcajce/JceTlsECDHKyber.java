package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsPQCKemMode;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class JceTlsECDHKyber implements TlsAgreement
{
    protected final JceTlsECDHKyberDomain domain;

    protected KeyPair ecLocalKeyPair;
    protected PublicKey ecPeerPublicKey;
    protected AsymmetricCipherKeyPair kyberLocalKeyPair;
    protected KyberPublicKeyParameters kyberPeerPublicKey;

    protected byte[] kyberCiphertext;
    protected byte[] kyberSecret;

    public JceTlsECDHKyber(JceTlsECDHKyberDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.ecLocalKeyPair = domain.getEcDomain().generateKeyPair();
        byte[] ecKey = domain.getEcDomain().encodePublicKey(ecLocalKeyPair.getPublic());
        byte[] kyberKey;
        if (TlsPQCKemMode.PQC_KEM_CLIENT.equals(domain.getKyberDomain().getTlsPQCConfig().getTlsPQCKemMode()))
        {
            this.kyberLocalKeyPair = domain.getKyberDomain().generateKeyPair();
            kyberKey = domain.getKyberDomain().encodePublicKey((KyberPublicKeyParameters)kyberLocalKeyPair.getPublic());
        }
        else
        {
            kyberKey = Arrays.clone(kyberCiphertext);
        }
        return Arrays.concatenate(ecKey, kyberKey);
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        byte[] ecKey = Arrays.copyOf(peerValue, domain.getEcDomain().getPublicKeyByteLength());
        byte[] kyberKey = Arrays.copyOfRange(peerValue, domain.getEcDomain().getPublicKeyByteLength(), peerValue.length);
        this.ecPeerPublicKey = domain.getEcDomain().decodePublicKey(ecKey);

        if (TlsPQCKemMode.PQC_KEM_CLIENT.equals(domain.getKyberDomain().getTlsPQCConfig().getTlsPQCKemMode()))
        {
            this.kyberCiphertext = Arrays.clone(kyberKey);
        }
        else
        {
            this.kyberPeerPublicKey = domain.getKyberDomain().decodePublicKey(kyberKey);
            SecretWithEncapsulation encap = domain.getKyberDomain().enCap(kyberPeerPublicKey);
            this.kyberCiphertext = encap.getEncapsulation();
            kyberSecret = encap.getSecret();
        }
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] ecSecret = domain.getEcDomain().calculateECDHAgreementBytes(ecLocalKeyPair.getPrivate(), ecPeerPublicKey);
        if (TlsPQCKemMode.PQC_KEM_CLIENT.equals(domain.getKyberDomain().getTlsPQCConfig().getTlsPQCKemMode()))
        {
            kyberSecret = domain.getKyberDomain().deCap((KyberPrivateKeyParameters)kyberLocalKeyPair.getPrivate(), kyberCiphertext);
        }
        return domain.getKyberDomain().adoptLocalSecret(Arrays.concatenate(ecSecret, kyberSecret));
    }
}
