package org.bouncycastle.tls.crypto.impl.bc;

import java.io.IOException;
import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsPQCConfig;
import org.bouncycastle.tls.crypto.TlsPQCDomain;

public class BcTlsX448KyberDomain implements TlsPQCDomain
{
    protected final BcTlsKyberDomain kyberDomain;
    protected final BcTlsCrypto crypto;

    public BcTlsX448KyberDomain(BcTlsCrypto crypto, TlsPQCConfig pqcConfig)
    {
        this.kyberDomain = new BcTlsKyberDomain(crypto, pqcConfig);
        this.crypto = crypto;
    }

    public TlsAgreement createPQC()
    {
        return new BcTlsX448Kyber(this);
    }

    public BcTlsKyberDomain getKyberDomain()
    {
        return kyberDomain;
    }

    public byte[] generateX448PrivateKey() throws IOException
    {
        byte[] privateKey = new byte[X448.SCALAR_SIZE];
        crypto.getSecureRandom().nextBytes(privateKey);
        return privateKey;
    }

    public byte[] getX448PublicKey(byte[] privateKey) throws IOException
    {
        byte[] publicKey = new byte[X448.POINT_SIZE];
        X448.scalarMultBase(privateKey, 0, publicKey, 0);
        return publicKey;
    }

    public int getX448PublicKeyByteLength() throws IOException
    {
        return X448.POINT_SIZE;
    }

    public byte[] calculateX448Secret(byte[] privateKey, byte[] peerPublicKey) throws IOException
    {
        byte[] secret = new byte[X448.POINT_SIZE];
        if (!X448.calculateAgreement(privateKey, 0, peerPublicKey, 0, secret, 0))
        {
            throw new TlsFatalAlert(AlertDescription.handshake_failure);
        }
        return secret;
    }
}