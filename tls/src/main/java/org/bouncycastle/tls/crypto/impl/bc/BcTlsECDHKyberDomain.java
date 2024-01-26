package org.bouncycastle.tls.crypto.impl.bc;

import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECConfig;
import org.bouncycastle.tls.crypto.TlsPQCConfig;
import org.bouncycastle.tls.crypto.TlsPQCDomain;

public class BcTlsECDHKyberDomain implements TlsPQCDomain
{
    protected final BcTlsECDomain ecDomain;
    protected final BcTlsKyberDomain kyberDomain;

    public BcTlsECDHKyberDomain(BcTlsCrypto crypto, TlsPQCConfig pqcConfig)
    {
        this.ecDomain = getBcTlsECDomain(crypto, pqcConfig);
        this.kyberDomain = new BcTlsKyberDomain(crypto, pqcConfig);
    }
    
    public TlsAgreement createPQC()
    {
        return new BcTlsECDHKyber(this);
    }

    public BcTlsECDomain getEcDomain()
    {
        return ecDomain;
    }

    public BcTlsKyberDomain getKyberDomain()
    {
        return kyberDomain;
    }
    
    private BcTlsECDomain getBcTlsECDomain(BcTlsCrypto crypto, TlsPQCConfig pqcConfig)
    {
        switch (pqcConfig.getNamedGroup())
        {
        case NamedGroup.secp256Kyber512:
            return new BcTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp256r1));
        case NamedGroup.secp384Kyber768:
            return new BcTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp384r1));
        case NamedGroup.secp521Kyber1024:
            return new BcTlsECDomain(crypto, new TlsECConfig(NamedGroup.secp521r1));
        default:
            return null;
        }
    }
}