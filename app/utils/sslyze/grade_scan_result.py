from typing import Tuple, List, Set

import app.db_models as db_models
from loguru import logger
from enum import Enum


# The following grades are named correspondingly to defacto industry standard - SSLLabs
# However the same configuration might not warrant same grade letter
# because the rules for determining it are not exactly same.
# https://github.com/ssllabs/research/wiki/SSL-Labs-Assessment-Policy-v2017

class Grades(Enum):
    A_plus = 1
    A = 2
    B = 3
    C = 4
    D = 5
    E = 6
    F = 7
    T = 8  # Not publicly trusted
    M = 9  # Not valid certificate.
    Some_scan_failed = 10


def grade_scan_result(
        scan_result: db_models.ScanResults,
    partial_simplified: db_models.ScanResultsSimplified,
) -> Tuple[str, List[str]]:
    tmp = GradeResult(scan_result, partial_simplified)
    return tmp.get_result()


class GradeResult(object):
    def __init__(
        self,
        scan_result: db_models.ScanResults,
        partial_simplified: db_models.ScanResultsSimplified,
    ):
        self.grade_cap = Grades.A_plus
        self.grade_cap_reasons = []
        self.scan_result = scan_result
        self.partial_simplified = partial_simplified
        self.partial_fail = False

    def _format_msg_and_cap(self, new_cap: Grades, reason: str):
        msg = f"Capped at {new_cap.name} because the server {reason}"
        self.grade_cap_reasons.append(msg)

        res_cap_int = max(self.grade_cap.value, new_cap.value)
        self.grade_cap = Grades(res_cap_int)

    def _calculate(self):
        all_ssl_tls_names = [
            "sslv2",
            "sslv3",
            "tlsv1",
            "tlsv11",
            "tlsv12",
            "tlsv13",
        ]
        for single_ssl_tls_name in all_ssl_tls_names:
            if getattr(self.scan_result, single_ssl_tls_name) is None:
                self._format_msg_and_cap(
                    Grades.Some_scan_failed,
                    f"Scan of {single_ssl_tls_name} failed. The resulting grade might not be accurate",
                )
                self.partial_fail = True

        self.calculate_certificate()
        self.calculate_protocol()
        self.calculate_cipher_strength()
        self.calculate_renegotiation()
        self.calculate_headers()
        self.calculate_vulnerabilities()
        # calculate_key_exchange
        # calculate_cipher_length

    def get_result(self) -> Tuple[str, List[str]]:
        self._calculate()
        return self.grade_cap.name, self.grade_cap_reasons

    def calculate_certificate(self):
        certificate = self.scan_result.certificate_information
        if certificate is None:
            logger.error("SC0012 ScanResult has no certificate info object associated")
            return
        if not certificate.leaf_certificate_has_must_staple_extension:
            self._format_msg_and_cap(Grades.A, "has no must have staple extensions")
        if not certificate.leaf_certificate_signed_certificate_timestamps_count:
            self._format_msg_and_cap(Grades.T, "certificate is not signed")
        if not certificate.received_chain_contains_anchor_certificate:
            self._format_msg_and_cap(Grades.A, "has no anchor certificate")
        if certificate.verified_chain_has_sha1_signature:
            self._format_msg_and_cap(Grades.B, "verified chain has SHA1 signature")
        if certificate.leaf_certificate_is_ev:
            self._format_msg_and_cap(Grades.A_plus, "has extended validation")
        if not certificate.received_chain_has_valid_order:
            self._format_msg_and_cap(Grades.A, "has invalid certificate chain order")  # ask for severity
        if certificate.ocsp_response_is_trusted:
            self._format_msg_and_cap(Grades.A_plus, "is OCSP trusted")

    def calculate_protocol(self):
        if self.partial_simplified.sslv2_working_ciphers_count:
            self._format_msg_and_cap(Grades.F, "supports SSLv2")
        if self.partial_simplified.sslv3_working_ciphers_count:
            self._format_msg_and_cap(Grades.B, "supports SSLv3")
        if self.partial_simplified.tlsv10_working_ciphers_count:
            self._format_msg_and_cap(Grades.B, "supports TLS 1.0")
        if self.partial_simplified.tlsv11_working_ciphers_count:
            self._format_msg_and_cap(Grades.B, "supports TLS 1.1")
        if self.partial_simplified.tlsv12_working_ciphers_count:
            self._format_msg_and_cap(Grades.A, "supports TLS 1.2")
        if self.partial_simplified.tlsv13_working_ciphers_count:
            self._format_msg_and_cap(Grades.A_plus, "supports TLS 1.3")

    def calculate_headers(self):
        sec_header: db_models.HTTPSecurityHeaders = self.scan_result.http_security_headers
        if sec_header is None:
            logger.error("SC0013 ScanResult has no http security headers object associated")
            return
        if sec_header.strict_transport_security_header and \
                sec_header.public_key_pins_header:
            self._format_msg_and_cap(Grades.A_plus, "supports HKPK and HSPS")
        elif sec_header.strict_transport_security_header:
            self._format_msg_and_cap(Grades.A, "supports HSPS")

    def calculate_renegotiation(self):
        renegotiation = self.scan_result.session_renegotiation
        if renegotiation is None:
            logger.error("SC0014 ScanResult has no renegotiation object associated")
            return
        if renegotiation.supports_secure_renegotiation:
            self._format_msg_and_cap(Grades.A_plus, "supports secure client renegotiation")
        else:
            self._format_msg_and_cap(Grades.F, "supports client renegotiation, but is not secure")

    def calculate_cipher_strength(self):
        if self.partial_simplified.tlsv13_working_weak_ciphers_count is not None:
            self._format_msg_and_cap(Grades.A, "has TLS 1.3 with weak ciphers")
        if self.partial_simplified.tlsv12_working_weak_ciphers_count is not None:
            self._format_msg_and_cap(Grades.A, "has TLS 1.2 with weak ciphers")
        elif self.partial_simplified.tlsv11_working_weak_ciphers_count is not None:
            self._format_msg_and_cap(Grades.B, "has TLS 1.1 with weak ciphers")

    def calculate_vulnerabilities(self):
        if self.scan_result.openssl_ccs_injection is not None and self.scan_result.openssl_ccs_injection.is_vulnerable_to_ccs_injection:
            self._format_msg_and_cap(Grades.F, "Vulnerable to CSS injection")
        if self.scan_result.openssl_heartbleed is not None and self.scan_result.openssl_heartbleed.is_vulnerable_to_heartbleed:
            self._format_msg_and_cap(Grades.F, "Vulnerable to heartbleed")
        if self.scan_result.downgrade_attacks is not None and not self.scan_result.downgrade_attacks.supports_fallback_scsv:
            self._format_msg_and_cap(Grades.F, "Vulnerable to downgrade attacks")