from typing import Tuple, List

import app.db_models as db_models
from loguru import logger
from enum import Enum


# The following grades are named correspondingly to defacto industry standard - SSLLabs
# However the same configuration might not warrant same grade letter, the rules for determining it are not exactly same.
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


def grade_scan_result(scan_result: db_models.ScanResults, partial_simplified: db_models.ScanResultsSimplified)\
        -> Tuple[str, List[str]]:
    tmp = GradeResult(scan_result, partial_simplified)
    return tmp.get_result()


class GradeResult(object):
    def __init__(self, scan_result: db_models.ScanResults, partial_simplified: db_models.ScanResultsSimplified):
        self.grade_cap = Grades.A_plus
        self.grade_cap_reasons = []
        self.scan_result = scan_result
        self.partial_simplified = partial_simplified
        self.partial_fail = False

    def _format_msg_and_cap(self, new_cap: Grades, reason: str):
        msg = f'Capped at {new_cap.name} because the server {reason}'
        self.grade_cap_reasons.append(msg)

        res_cap_int = max(self.grade_cap.value, new_cap.value)
        self.grade_cap = Grades(res_cap_int)

    def _calculate(self):
        all_ssl_tls_names = ["sslv2", "sslv3", "tlsv1", "tlsv11", "tlsv12", "tlsv13"]
        for single_ssl_tls_name in all_ssl_tls_names:
            if getattr(self.scan_result, single_ssl_tls_name) is None:
                self._format_msg_and_cap(
                    Grades.Some_scan_failed,
                    f"Scan of {single_ssl_tls_name} failed. The resulting grade might not be accurate."
                )
                self.partial_fail = True

        if self.partial_simplified.sslv2_working_ciphers_count:
            self._format_msg_and_cap(Grades.F, "supports SSLv2")

        if self.partial_simplified.sslv3_working_ciphers_count:
            self._format_msg_and_cap(Grades.D, "supports SSLv3")

        if self.partial_simplified.tlsv10_working_ciphers_count:
            self._format_msg_and_cap(Grades.B, "supports TLS 1.0")

        if self.partial_simplified.tlsv11_working_ciphers_count:
            self._format_msg_and_cap(Grades.B, "supports TLS 1.1")

        if self.partial_simplified.tlsv11_working_weak_ciphers_count == 0:
            self._format_msg_and_cap(Grades.A, "doesn't support TLS 1.3")

        if self.partial_simplified.tlsv13_working_weak_ciphers_count == 0 and \
                self.partial_simplified.tlsv12_working_weak_ciphers_count == 0:
            self._format_msg_and_cap(Grades.B, "doesn't support either TLS 1.2 or TLS 1.3")

    def get_result(self) -> Tuple[str, List[str]]:
        self._calculate()
        return self.grade_cap.name, self.grade_cap_reasons
