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

public class JceTlsX25519Kyber implements TlsAgreement
{
    protected final JceTlsX25519KyberDomain domain;

    protected KeyPair x25519LocalKeyPair;
    protected PublicKey x25519PeerPublicKey;
    protected AsymmetricCipherKeyPair kyberLocalKeyPair;
    protected KyberPublicKeyParameters kyberPeerPublicKey;

    protected byte[] kyberCiphertext;
    protected byte[] kyberSecret;

    public JceTlsX25519Kyber(JceTlsX25519KyberDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.x25519LocalKeyPair = domain.generateX25519KeyPair();
        byte[] x25519Key = domain.encodeX25519PublicKey(x25519LocalKeyPair.getPublic());
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
        return Arrays.concatenate(x25519Key, kyberKey);
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        byte[] xdhKey = Arrays.copyOf(peerValue, domain.getX25519PublicKeyByteLength());
        byte[] kyberKey = Arrays.copyOfRange(peerValue, domain.getX25519PublicKeyByteLength(), peerValue.length);
        this.x25519PeerPublicKey = domain.decodeX25519PublicKey(xdhKey);

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
        byte[] x25519Secret = domain.calculateX25519AgreementToBytes(x25519LocalKeyPair.getPrivate(), x25519PeerPublicKey);
        if (TlsPQCKemMode.PQC_KEM_CLIENT.equals(domain.getKyberDomain().getTlsPQCConfig().getTlsPQCKemMode()))
        {
            kyberSecret = domain.getKyberDomain().deCap((KyberPrivateKeyParameters)kyberLocalKeyPair.getPrivate(), kyberCiphertext);
        }
        return domain.getKyberDomain().adoptLocalSecret(Arrays.concatenate(x25519Secret, kyberSecret));
    }
}
