package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
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

public class JceTlsX448Kyber implements TlsAgreement
{
    protected final JceTlsX448KyberDomain domain;

    protected KeyPair x448LocalKeyPair;
    protected PublicKey x448PeerPublicKey;
    protected AsymmetricCipherKeyPair kyberLocalKeyPair;
    protected KyberPublicKeyParameters kyberPeerPublicKey;

    protected byte[] kyberCiphertext;
    protected byte[] kyberSecret;

    public JceTlsX448Kyber(JceTlsX448KyberDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.x448LocalKeyPair = domain.generateX448KeyPair();
        byte[] x448Key = domain.encodeX448PublicKey(x448LocalKeyPair.getPublic());
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
        return Arrays.concatenate(x448Key, kyberKey);
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        byte[] xdhKey = Arrays.copyOf(peerValue, domain.getX448PublicKeyByteLength());
        byte[] kyberKey = Arrays.copyOfRange(peerValue, domain.getX448PublicKeyByteLength(), peerValue.length);
        this.x448PeerPublicKey = domain.decodeX448PublicKey(xdhKey);

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
        byte[] x448Secret = domain.calculateX448AgreementToBytes(x448LocalKeyPair.getPrivate(), x448PeerPublicKey);

        if (TlsPQCKemMode.PQC_KEM_CLIENT.equals(domain.getKyberDomain().getTlsPQCConfig().getTlsPQCKemMode()))
        {
            kyberSecret = domain.getKyberDomain().deCap((KyberPrivateKeyParameters)kyberLocalKeyPair.getPrivate(), kyberCiphertext);
        }
        
        return domain.getKyberDomain().adoptLocalSecret(Arrays.concatenate(x448Secret, kyberSecret));
    }
}
