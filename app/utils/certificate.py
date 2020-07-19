from OpenSSL import crypto


def certificate_thumbprint(crt_string, digest_type="sha1"):
    crt = bytes(crt_string, 'utf-8')
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, crt)
    # logger.debug(cert.get_subject())

    # logger.debug(f"sha256: {cert.digest('sha1')}")
    # logger.debug(f"sha256: {cert.digest('sha256')}")

    return cert.digest(digest_type).decode("utf-8")
