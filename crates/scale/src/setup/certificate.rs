use std::io;
use std::mem::size_of;
use std::ptr::{NonNull, null_mut};

use windows::Win32::Security::Cryptography::{
    CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, CERT_CHAIN_CONTEXT, CERT_CHAIN_DISABLE_AIA,
    CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE, CERT_CHAIN_ENGINE_CONFIG, CERT_CHAIN_PARA,
    CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_STORE_ADD_NEW, CERT_STORE_PROV_MEMORY,
    CERT_TRUST_NO_ERROR, CertAddEncodedCertificateToStore, CertCloseStore,
    CertCreateCertificateChainEngine, CertCreateCertificateContext, CertFreeCertificateChain,
    CertFreeCertificateChainEngine, CertFreeCertificateContext, CertGetCertificateChain,
    CertOpenStore, HCERTCHAINENGINE, HCERTSTORE, X509_ASN_ENCODING,
};

const MIJIA_ROOT: &[u8] = include_bytes!("mijia-root.der");
const LOCAL_TEST_CERTIFICATE: &[u8] = include_bytes!("s200-local-test.der");
const OFFLINE_CHAIN_FLAGS: u32 = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
    | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE
    | CERT_CHAIN_DISABLE_AIA;

/// Checks the bundled self-signed certificate with Mijia Root as the sole trust anchor.
pub fn check_setup_test_certificate() -> io::Result<()> {
    check_chain(LOCAL_TEST_CERTIFICATE, MIJIA_ROOT)
}

fn check_chain(der: &[u8], root_der: &[u8]) -> io::Result<()> {
    // SAFETY: Windows copies DER out of the slice. The guard releases the context.
    let certificate = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der) };
    let certificate = Certificate(NonNull::new(certificate).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the certificate is not valid X.509 DER",
        )
    })?);

    // SAFETY: There are no provider parameters for an in-memory certificate store.
    let roots = RootStore(unsafe {
        CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            X509_ASN_ENCODING,
            None,
            CERT_OPEN_STORE_FLAGS(0),
            None,
        )?
    });
    // SAFETY: The store is open, and the call copies the root certificate.
    unsafe {
        CertAddEncodedCertificateToStore(
            Some(roots.0),
            X509_ASN_ENCODING,
            root_der,
            CERT_STORE_ADD_NEW,
            None,
        )?;
    }

    let config = CERT_CHAIN_ENGINE_CONFIG {
        cbSize: size_of::<CERT_CHAIN_ENGINE_CONFIG>() as u32,
        hExclusiveRoot: roots.0,
        dwFlags: OFFLINE_CHAIN_FLAGS,
        ..Default::default()
    };
    let mut engine = HCERTCHAINENGINE::default();
    // SAFETY: The configuration is valid and the store outlives the chain engine.
    unsafe { CertCreateCertificateChainEngine(&config, &mut engine)? };
    let engine = ChainEngine(engine);

    let parameters = CERT_CHAIN_PARA {
        cbSize: size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    let mut chain = null_mut::<CERT_CHAIN_CONTEXT>();
    // SAFETY: The engine and certificate are live, and the output slot is writable.
    unsafe {
        CertGetCertificateChain(
            Some(engine.0),
            certificate.0.as_ptr(),
            None,
            None,
            &parameters,
            OFFLINE_CHAIN_FLAGS,
            None,
            &mut chain,
        )?;
    }
    let chain = NonNull::new(chain)
        .ok_or_else(|| io::Error::other("Windows did not return a certificate chain"))?;
    // SAFETY: The successful call returned an owned chain. Read its status before freeing it.
    let status = unsafe {
        let status = chain.as_ref().TrustStatus.dwErrorStatus;
        CertFreeCertificateChain(chain.as_ptr());
        status
    };
    if status == CERT_TRUST_NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("certificate chain rejected by Mijia Root (status 0x{status:08X})"),
        ))
    }
}

struct Certificate(NonNull<CERT_CONTEXT>);

impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: This guard owns the single certificate context.
        let _ = unsafe { CertFreeCertificateContext(Some(self.0.as_ptr())) };
    }
}

struct RootStore(HCERTSTORE);

impl Drop for RootStore {
    fn drop(&mut self) {
        // SAFETY: This guard owns the open in-memory store.
        let _ = unsafe { CertCloseStore(Some(self.0), 0) };
    }
}

struct ChainEngine(HCERTCHAINENGINE);

impl Drop for ChainEngine {
    fn drop(&mut self) {
        // SAFETY: This guard owns the chain engine, and its root store is still open.
        unsafe { CertFreeCertificateChainEngine(Some(self.0)) };
    }
}

#[cfg(test)]
mod tests {
    use super::{MIJIA_ROOT, check_chain, check_setup_test_certificate};
    use std::io::ErrorKind;

    #[test]
    fn rejects_self_signed_test_certificate() {
        assert!(
            matches!(check_setup_test_certificate(), Err(error) if error.kind() == ErrorKind::PermissionDenied)
        );
    }

    #[test]
    fn rejects_malformed_der() {
        assert!(
            matches!(check_chain(b"not a certificate", MIJIA_ROOT), Err(error) if error.kind() == ErrorKind::InvalidData)
        );
    }
}
