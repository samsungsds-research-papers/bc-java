package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsPQCConfig;
import org.bouncycastle.tls.crypto.TlsPQCDomain;

public class JceTlsECDHKyberDomain implements TlsPQCDomain
{
    protected final JceTlsECDomain ecDomain;
    protected final JceTlsKyberDomain kyberDomain;

    public JceTlsECDHKyberDomain(JcaTlsCrypto crypto, TlsPQCConfig pqcConfig)
    {
        this.ecDomain = getJceTlsECDomain(crypto, pqcConfig);
        this.kyberDomain = new JceTlsKyberDomain(crypto, pqcConfig);
    }

    public TlsAgreement createPQC()
    {
        return new JceTlsECDHKyber(this);
    }

    public JceTlsECDomain getEcDomain()
    {
        return ecDomain;
    }

    public JceTlsKyberDomain getKyberDomain()
    {
        return kyberDomain;
    }
    
    private JceTlsECDomain getJceTlsECDomain(JcaTlsCrypto crypto, TlsPQCConfig pqcConfig)
    {
        switch (pqcConfig.getNamedGroup())
        {
        case NamedGroup.secp256Kyber512:
            return new JceTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp256r1));
        case NamedGroup.secp384Kyber768:
            return new JceTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp384r1));
        case NamedGroup.secp521Kyber1024:
            return new JceTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp521r1));
        default:
            return null;
        }
    }
}
