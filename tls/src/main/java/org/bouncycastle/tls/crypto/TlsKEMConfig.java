package org.bouncycastle.tls.crypto;

public class TlsKEMConfig
{
    protected final int namedGroup;
    protected final TlsCryptoParameters cryptoParams;
    protected final int kemNamedGroup;

    public TlsKEMConfig(int namedGroup, TlsCryptoParameters cryptoParams)
    {
        this.namedGroup = namedGroup;
        this.cryptoParams = cryptoParams;
        this.kemNamedGroup = getKEMNamedGroup(namedGroup);
    }
    
    public int getNamedGroup()
    {
        return namedGroup;
    }
    
    public boolean isServer()
    {
        return cryptoParams.isServer();
    }

    public int getKEMNamedGroup()
    {
        return kemNamedGroup;
    }
    
    private int getKEMNamedGroup(int namedGroup)
    {
        return namedGroup;
        // switch (namedGroup)
        // {
        // case NamedGroup.mlkem512:
        // case NamedGroup.secp256Mlkem512:
        // case NamedGroup.x25519Mlkem512:
        //     return NamedGroup.mlkem512;
        // case NamedGroup.mlkem768:
        // case NamedGroup.secp384Mlkem768:
        // case NamedGroup.x25519Mlkem768:
        // case NamedGroup.x448Mlkem768:
        //     return NamedGroup.mlkem768;
        // case NamedGroup.Mlkem1024:
        // case NamedGroup.secp521Mlkem1024:
        //     return NamedGroup.mlkem1024;
        // default:
        //     return namedGroup;
        // }
    }
}
