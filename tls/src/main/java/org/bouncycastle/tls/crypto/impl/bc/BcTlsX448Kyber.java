package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsPQCKemMode;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

public class BcTlsX448Kyber implements TlsAgreement
{
    protected final BcTlsX448KyberDomain domain;

    protected AsymmetricCipherKeyPair kyberLocalKeyPair;
    protected KyberPublicKeyParameters kyberPeerPublicKey;
    protected byte[] x448PrivateKey;
    protected byte[] x448PeerPublicKey;

    protected byte[] kyberCiphertext;
    protected byte[] kyberSecret;

    public BcTlsX448Kyber(BcTlsX448KyberDomain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.x448PrivateKey = domain.generateX448PrivateKey();
        byte[] x448Key = domain.getX448PublicKey(x448PrivateKey);
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
        this.x448PeerPublicKey = Arrays.copyOf(peerValue, domain.getX448PublicKeyByteLength());
        byte[] kyberKey = Arrays.copyOfRange(peerValue, domain.getX448PublicKeyByteLength(), peerValue.length);
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
        byte[] x448Secret = domain.calculateX448Secret(x448PrivateKey, x448PeerPublicKey);
        if (TlsPQCKemMode.PQC_KEM_CLIENT.equals(domain.getKyberDomain().getTlsPQCConfig().getTlsPQCKemMode()))
        {
            kyberSecret = domain.getKyberDomain().deCap((KyberPrivateKeyParameters)kyberLocalKeyPair.getPrivate(), kyberCiphertext);
        }
        return domain.getKyberDomain().adoptLocalSecret(Arrays.concatenate(x448Secret, kyberSecret));
    }
}