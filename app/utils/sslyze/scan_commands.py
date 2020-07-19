from loguru import logger

# todo: check that the following imports will never try to import from the current folder, i.e. sslyze
import sslyze
from sslyze.plugins.plugins_repository import PluginsRepository

KNOWN_SCAN_COMMANDS = {
    "CertificateInfoScanCommand": sslyze.plugins.certificate_info_plugin.CertificateInfoScanCommand,
    "CompressionScanCommand": sslyze.plugins.compression_plugin.CompressionScanCommand,
    "HeartbleedScanCommand": sslyze.plugins.heartbleed_plugin.HeartbleedScanCommand,
    "Tlsv11ScanCommand": sslyze.plugins.openssl_cipher_suites_plugin.Tlsv11ScanCommand,
    "Tlsv10ScanCommand": sslyze.plugins.openssl_cipher_suites_plugin.Tlsv10ScanCommand,
    "FallbackScsvScanCommand": sslyze.plugins.fallback_scsv_plugin.FallbackScsvScanCommand,
    "Sslv30ScanCommand": sslyze.plugins.openssl_cipher_suites_plugin.Sslv30ScanCommand,
    "HttpHeadersScanCommand": sslyze.plugins.http_headers_plugin.HttpHeadersScanCommand,
    "OpenSslCcsInjectionScanCommand": sslyze.plugins.openssl_ccs_injection_plugin.OpenSslCcsInjectionScanCommand,
    "SessionResumptionRateScanCommand": sslyze.plugins.session_resumption_plugin.SessionResumptionRateScanCommand,
    "RobotScanCommand": sslyze.plugins.robot_plugin.RobotScanCommand,
    "Sslv20ScanCommand": sslyze.plugins.openssl_cipher_suites_plugin.Sslv20ScanCommand,
    "EarlyDataScanCommand": sslyze.plugins.early_data_plugin.EarlyDataScanCommand,
    "SessionResumptionSupportScanCommand": sslyze.plugins.session_resumption_plugin.SessionResumptionSupportScanCommand,
    "SessionRenegotiationScanCommand": sslyze.plugins.session_renegotiation_plugin.SessionRenegotiationScanCommand,
    "Tlsv13ScanCommand": sslyze.plugins.openssl_cipher_suites_plugin.Tlsv13ScanCommand,
    "Tlsv12ScanCommand": sslyze.plugins.openssl_cipher_suites_plugin.Tlsv12ScanCommand,
}


def from_names_to_scan_commands(csv_command_names: str) -> list:
    # todo: it would be nice to have the config validated at the start, not at the first run of scanner
    #  currently it's would be circular dependency, consider.

    if True:  # a sanity check for when the number of scan commands changes
        plugins_repository = PluginsRepository()
        commands = plugins_repository.get_available_commands()
        if len(commands) != len(KNOWN_SCAN_COMMANDS):
            logger.warning("The number of SSLyze plugins does not match the number of hardcoded scan commands.")

    if csv_command_names == "DONT_LIMIT":
        return list(KNOWN_SCAN_COMMANDS.values())

    answer = []
    command_names_arr = list(set([x.strip() for x in csv_command_names.split(",")]))
    for cmd_name in command_names_arr:
        if cmd_name in KNOWN_SCAN_COMMANDS:
            answer.append(KNOWN_SCAN_COMMANDS[cmd_name])
        else:
            logger.warning("Unknown SSLyze Scan Command")
    return answer

