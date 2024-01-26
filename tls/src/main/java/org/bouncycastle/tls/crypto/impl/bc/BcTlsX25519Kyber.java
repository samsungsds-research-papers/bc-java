package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsPQCKemMode;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class BcTlsX25519Kyber implements TlsAgreement
{
    protected final BcTlsX25519KyberDomain domain;

    protected AsymmetricCipherKeyPair kyberLocalKeyPair;
    protected KyberPublicKeyParameters kyberPeerPublicKey;
    protected byte[] x25519PrivateKey;
    protected byte[] x25519PeerPublicKey;

    protected byte[] kyberCiphertext;
    protected byte[] kyberSecret;

    public BcTlsX25519Kyber(BcTlsX25519KyberDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.x25519PrivateKey = domain.generateX25519PrivateKey();
        byte[] x25519Key = domain.getX25519PublicKey(x25519PrivateKey);
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
        this.x25519PeerPublicKey = Arrays.copyOf(peerValue, domain.getX25519PublicKeyByteLength());
        byte[] kyberKey = Arrays.copyOfRange(peerValue, domain.getX25519PublicKeyByteLength(), peerValue.length);
        if (TlsPQCKemMode.PQC_KEM_CLIENT.equals(domain.getKyberDomain().getTlsPQCConfig().getTlsPQCKemMode()))
        {
            this.kyberCiphertext = Arrays.clone(kyberKey);
        }
        else
        {
            this.kyberPeerPublicKey = domain.getKyberDomain().decodePublicKey(kyberKey);
            SecretWithEncapsulation encap = domain.getKyberDomain().enCap(kyberPeerPublicKey);
            kyberCiphertext = encap.getEncapsulation();
            kyberSecret = encap.getSecret();
        }
    }

    public TlsSecret calculateSecret() throws IOException
    {
        byte[] x25519Secret = domain.calculateX25519Secret(x25519PrivateKey, x25519PeerPublicKey);
        if (TlsPQCKemMode.PQC_KEM_CLIENT.equals(domain.getKyberDomain().getTlsPQCConfig().getTlsPQCKemMode()))
        {
            kyberSecret = domain.getKyberDomain().deCap((KyberPrivateKeyParameters)kyberLocalKeyPair.getPrivate(), kyberCiphertext);
        }
        return domain.getKyberDomain().adoptLocalSecret(Arrays.concatenate(x25519Secret, kyberSecret));
    }
}