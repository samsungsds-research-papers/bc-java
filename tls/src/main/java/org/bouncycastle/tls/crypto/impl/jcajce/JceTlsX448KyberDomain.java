package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.math.ec.rfc7748.X448;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCryptoException;
import org.bouncycastle.tls.crypto.TlsPQCConfig;
import org.bouncycastle.tls.crypto.TlsPQCDomain;
import org.bouncycastle.util.Arrays;

public class JceTlsX448KyberDomain implements TlsPQCDomain
{
    protected final JceTlsKyberDomain kyberDomain;
    protected final JceX448Domain x448Domain;
    protected final JcaTlsCrypto crypto;

    public JceTlsX448KyberDomain(JcaTlsCrypto crypto, TlsPQCConfig pqcConfig)
    {
        this.kyberDomain = new JceTlsKyberDomain(crypto, pqcConfig);
        this.crypto = crypto;
        this.x448Domain = new JceX448Domain(crypto);
    }

    public TlsAgreement createPQC()
    {
        return new JceTlsX448Kyber(this);
    }

    public JceTlsKyberDomain getKyberDomain()
    {
        return kyberDomain;
    }

    public KeyPair generateX448KeyPair()
    {
        try
        {
            return x448Domain.generateKeyPair();
        }
        catch (Exception e)
        {
            throw Exceptions.illegalStateException("unable to create key pair: " + e.getMessage(), e);
        }
    }

    public byte[] encodeX448PublicKey(PublicKey publicKey) throws IOException
    {
        return XDHUtil.encodePublicKey(publicKey);
    }

    public int getX448PublicKeyByteLength() throws IOException
    {
        return X448.POINT_SIZE;
    }

    public PublicKey decodeX448PublicKey(byte[] x448Key) throws IOException
    {
        return x448Domain.decodePublicKey(x448Key);
    }

    public byte[] calculateX448AgreementToBytes(PrivateKey privateKey, PublicKey publicKey) throws IOException
    {
        try
        {
            byte[] secret =  crypto.calculateKeyAgreement("X448", privateKey, publicKey, "TlsPremasterSecret");
            if (secret == null || secret.length != 56)
            {
                throw new TlsCryptoException("invalid secret calculated");
            }
            if (Arrays.areAllZeroes(secret, 0, secret.length))
            {
                throw new TlsFatalAlert(AlertDescription.handshake_failure);
            }
            return secret;
        }
        catch (GeneralSecurityException e)
        {
            throw new TlsCryptoException("cannot calculate secret", e);
        }
    }
}