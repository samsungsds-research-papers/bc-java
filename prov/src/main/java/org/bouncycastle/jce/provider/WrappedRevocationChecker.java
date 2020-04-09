package org.bouncycastle.jce.provider;

import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.PKIXCertPathChecker;

import org.bouncycastle.jcajce.PKIXCertRevocationChecker;
import org.bouncycastle.jcajce.PKIXCertRevocationCheckerParameters;

class WrappedRevocationChecker
    implements PKIXCertRevocationChecker
{
    private final PKIXCertPathChecker checker;

    public WrappedRevocationChecker(PKIXCertPathChecker checker)
    {
        this.checker = checker;
    }

    @Override
    public void initialize(PKIXCertRevocationCheckerParameters params)
    {
         // ignore.
    }

    @Override
    public void check(Certificate cert)
        throws CertPathValidatorException
    {
        checker.check(cert);
    }
}