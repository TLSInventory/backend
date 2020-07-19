import datetime
# import functools
import random
from loguru import logger

from flask_sqlalchemy import event
from sqlalchemy.orm import class_mapper, ColumnProperty
from sqlalchemy.types import TypeDecorator

from typing import Optional

import app
import app.utils.db.basic as db_utils
from sslyze.ssl_settings import TlsWrappedProtocolEnum

from config import SchedulerConfig

db = app.db
Base = db.Model


# ----------- Helper -----------

class NumericTimestamp(TypeDecorator):
    impl = db.Integer

    def __init__(self):
        TypeDecorator.__init__(self)

    # def process_bind_param(self, value, dialect):
    #     if value is None:
    #         return None
    #     return int(value.timestamp())
    #
    # def process_result_value(self, value, dialect):
    #     return datetime.datetime.utcfromtimestamp(value)  # todo: timezone?


def datetime_to_timestamp(x: datetime.datetime) -> int:
    if x is None:
        return None
    return int(x.timestamp())


def timestamp_to_datetime(x: int) -> datetime.datetime:
    return datetime.datetime.utcfromtimestamp(x)


class UniqueModel(object):
    @classmethod
    def from_kwargs(cls, obj) -> Optional[int]:
        if obj is None:
            return None
        res, returned_from_select = db_utils.get_one_or_create(cls, **obj)
        return res.id

    @classmethod
    # @functools.lru_cache(maxsize=2048)
    def select_from_list(cls, id_stringlist: str):
        if id_stringlist is None:
            return []
        stringlist_as_tuple = db_utils.split_array_to_tuple(id_stringlist)
        res = db.session \
            .query(cls) \
            .filter(cls.id.in_(stringlist_as_tuple)) \
            .all()
        res_resorted = sorted(res, key=lambda x: stringlist_as_tuple.index(x.id))
        return res_resorted  # original order is important in some cases

    @classmethod
    def attribute_names(cls):
        return [prop.key for prop in class_mapper(cls).iterate_properties
                if isinstance(prop, ColumnProperty)]


@event.listens_for(Base, 'before_update', propagate=True)
def receive_before_update(mapper, connection, target):
    # Respect the restrictions made by SQLAlchemy. Check before any modifications to DB.
    # This does not solve the update for ScanOrderMinimal.
    if hasattr(target, '__noUpdate__'):
        logger.error(f"Delete of record in table with noUpdate: {type(target)}")


@event.listens_for(Base, 'before_delete', propagate=True)
def receive_before_delete(mapper, connection, target):
    # Respect the restrictions made by SQLAlchemy. Check before any modifications to DB.
    # This does not solve the update for ScanOrderMinimal.
    if hasattr(target, '__noUpdate__'):
        logger.error(f"Delete of record in table with noUpdate: {type(target)}")


# ----------- Users -----------

class User(Base):  # todo
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String, unique=True, index=True, nullable=False)
    email = db.Column(db.String)
    password_hash = db.Column(db.String)
    main_api_key = db.Column(db.String, unique=True)


# ----------- Scheduling -----------

class Target(Base, UniqueModel):
    __tablename__ = 'targets'
    __noUpdate__ = True
    __uniqueColumns__ = ['hostname', 'port', 'ip_address', 'protocol']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    def __init__(self, *args, **kwargs):  # for custom defaults
        db_utils.set_attr_if_none(kwargs, "port", 443)
        db_utils.set_attr_if_none(kwargs, "protocol", TlsWrappedProtocolEnum.HTTPS)
        super().__init__(*args, **kwargs)

    id = db.Column(db.Integer, primary_key=True)

    hostname = db.Column(db.String, nullable=False)
    port = db.Column(db.Integer)  # default is being done by overloaded init
    ip_address = db.Column(db.String, default=None)
    protocol = db.Column(db.Enum(TlsWrappedProtocolEnum))  # default is being done by overloaded init

    def __str__(self):
        return f"{self.hostname}:{self.port}@{self.ip_address}"

    def __repr__(self):
        return f"{self.hostname}#{self.port}@{self.ip_address}?{self.protocol}"

    @classmethod
    def from_repr_to_transient(cls, str_repr):
        hostname_port, ip_address_tls_protocol = str_repr.split("@")
        hostname, port = hostname_port.split("#")
        ip_address, tls_protocol = ip_address_tls_protocol.split("?")
        _, tls_protocol_enum_name = tls_protocol.split(".")
        res = cls()
        res.hostname = hostname
        res.port = port
        res.ip_address = ip_address
        res.protocol = TlsWrappedProtocolEnum[tls_protocol_enum_name]
        return res

    def make_copy(self):
        return Target.from_repr_to_transient(repr(self))


class ScanOrder(Base, UniqueModel):
    __tablename__ = 'scanorders'
    __uniqueColumns__ = ['target_id', 'user_id']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)
    on_modification = True

    id = db.Column(db.Integer, primary_key=True)

    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False)
    target = db.relationship("Target")

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship("User")

    active = db.Column(db.Boolean, default=True)

    periodicity = db.Column(db.Integer, default=SchedulerConfig.default_target_scan_periodicity)  # in seconds


class ScanOrderMinimal(Base):
    __tablename__ = 'scanordersminimal'

    id = db.Column(db.Integer, db.ForeignKey('targets.id'), primary_key=True)
    target = db.relationship("Target")

    periodicity = db.Column(db.Integer)  # in seconds

    def __repr__(self):
        return f"ScanOrderMinimal({self.id}, {self.target}, {self.periodicity})"


class LastScan(Base, UniqueModel):  # this might not have to be in DB, it might be better in fast cache
    __tablename__ = 'lastscan'
    __uniqueColumns__ = ['target_id']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), unique=True)
    target = db.relationship("Target")

    last_scanned = db.Column(NumericTimestamp)
    last_enqueued = db.Column(NumericTimestamp)

    result_id = db.Column(db.Integer, db.ForeignKey('scanresults.id'))
    result = db.relationship("ScanResults")

    @classmethod
    def create_if_not_existent(cls, target_id):
        try:
            rand_time_offset = random.randrange(0, SchedulerConfig.max_first_scan_delay)
            enqueue_time = datetime.datetime.now() - datetime.timedelta(seconds=rand_time_offset)
            # res = LastScan(id=target_id, last_enqueued=int(enqueue_time.timestamp()))
            res = LastScan(target_id=target_id, last_enqueued=datetime_to_timestamp(enqueue_time))
            db.session.add(res)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.warning(f"Failed creating last_scan with error {e}")
            pass


# ----------- SSlyze -----------

class ServerInfo(Base, UniqueModel):
    __tablename__ = 'serverinfos'
    __noUpdate__ = True
    __uniqueColumns__ = ['hostname', 'port', 'ip_address', 'openssl_cipher_string_supported_id']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    hostname = db.Column(db.String)
    port = db.Column(db.Integer)
    ip_address = db.Column(db.String)

    openssl_cipher_string_supported_id = db.Column(db.Integer, db.ForeignKey('ciphers.id'))
    openssl_cipher_string_supported = db.relationship("CipherSuite")

    # future: I'm throwing out most of the data I don't set to server_info

    @staticmethod
    def from_dict(obj):
        return ServerInfo.from_parts(obj["openssl_name"], obj["ssl_version"], obj["is_anonymous"],
                                     obj["handshake_error_message"])


class TrustStore(Base, UniqueModel):
    __tablename__ = 'truststores'
    __noUpdate__ = True
    __uniqueColumns__ = ['name', 'version', 'ev_oids']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    # path = db.Column(db.String)
    name = db.Column(db.String)
    version = db.Column(db.String)
    ev_oids = db.Column(db.String)

    @staticmethod
    def from_dict(obj):
        return TrustStore.from_parts(obj["name"], obj["version"], ",".join(obj["ev_oids"]))

    @staticmethod
    # @functools.lru_cache(maxsize=1024)
    def from_parts(name, version, ev_oids):
        return TrustStore.from_kwargs({"name": name,
                                       "version": version,
                                       "ev_oids": ev_oids})


class Certificate(Base, UniqueModel):
    __tablename__ = 'certificates'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)

    as_pem = db.Column(db.String)
    hpkp_pin = db.Column(db.String)
    subject = db.Column(db.String)
    issuer = db.Column(db.String)
    serialNumber = db.Column(db.String)

    thumbprint_sha1 = db.Column(db.String)
    thumbprint_sha256 = db.Column(db.String, unique=True, index=True)

    notBefore = db.Column(db.DateTime)
    notAfter = db.Column(db.DateTime)

    signatureAlgorithm = db.Column(db.String)

    publicKey_algorithm = db.Column(db.String)
    publicKey_size = db.Column(db.Integer)
    publicKey_curve = db.Column(db.String)
    publicKey_exponent = db.Column(db.Integer)

    subject_alternative_name_list = db.Column(db.String)


class CipherSuiteScanResult(Base, UniqueModel):
    __tablename__ = 'ciphersuitescanresults'
    __noUpdate__ = True
    __uniqueColumns__ = ['protocol', 'preferred_cipher_id', 'accepted_cipher_list', 'rejected_cipher_list',
                         'errored_cipher_list']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    protocol = db.Column(
        db.String)  # should be ENUM, but as the sqllite doesn't natively support enums let's leave it as
    # string. This way it will also be as general as possible, so no change needed if for example TLS 1.4 is released.

    preferred_cipher_id = db.Column(db.Integer, db.ForeignKey('acceptedciphers.id'))
    preferred_cipher = db.relationship("AcceptedCipherSuite")

    accepted_cipher_list = db.Column(
        db.String)  # future: sqllite doesn't have arrays. If I make support, for postgres, then
    rejected_cipher_list = db.Column(db.String)  # future: let's make it array then. It would be cleaner.
    errored_cipher_list = db.Column(db.String)  # future:

    @staticmethod
    # @functools.lru_cache(maxsize=2048)
    def from_parts(openssl_name, ssl_version, is_anonymous):
        return CipherSuite.from_kwargs({"openssl_name": openssl_name,
                                        "ssl_version": ssl_version,
                                        "is_anonymous": is_anonymous})


class CipherSuite(Base, UniqueModel):
    __tablename__ = 'ciphers'
    __noUpdate__ = True
    __uniqueColumns__ = ['openssl_name', 'ssl_version']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    openssl_name = db.Column(db.String)
    ssl_version = db.Column(db.String)
    is_anonymous = db.Column(db.Boolean)

    @staticmethod
    # @functools.lru_cache(maxsize=1024)
    def from_parts(openssl_name, ssl_version, is_anonymous):
        return CipherSuite.from_kwargs({"openssl_name": openssl_name,
                                        "ssl_version": ssl_version,
                                        "is_anonymous": is_anonymous})

    @staticmethod
    # @functools.lru_cache(maxsize=1024)
    def id_from_parts(openssl_name, ssl_version):
        res = db.session.query(CipherSuite) \
            .filter(CipherSuite.openssl_name == openssl_name) \
            .filter(CipherSuite.ssl_version == ssl_version) \
            .one()
        return res.id


class RejectedCipherSuite(Base, UniqueModel):
    __tablename__ = 'rejectedciphers'
    __noUpdate__ = True
    __uniqueColumns__ = ['ciphersuite_id', 'handshake_error_message_id']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    ciphersuite_id = db.Column(db.Integer, db.ForeignKey('ciphers.id'))
    ciphersuite = db.relationship("CipherSuite")

    handshake_error_message_id = db.Column(db.Integer, db.ForeignKey('c_rejected_cipher_handshake_error_message.id'))
    handshake_error_message = db.relationship("RejectedCipherHandshakeErrorMessage")

    @staticmethod
    # @functools.lru_cache(maxsize=1024)
    def from_parts(openssl_name, ssl_version, is_anonymous, handshake_error_message):
        ciphersuite_id = CipherSuite.from_parts(openssl_name, ssl_version, is_anonymous)
        handshake_error_message_id = RejectedCipherHandshakeErrorMessage.from_parts(handshake_error_message)

        return RejectedCipherSuite.from_kwargs({"ciphersuite_id": ciphersuite_id,
                                                "handshake_error_message_id": handshake_error_message_id})

    @staticmethod
    def from_dict(obj):
        return RejectedCipherSuite.from_parts(obj["openssl_name"], obj["ssl_version"], obj["is_anonymous"],
                                              obj["handshake_error_message"])


class AcceptedCipherSuite(Base, UniqueModel):
    __tablename__ = 'acceptedciphers'
    __noUpdate__ = True
    __uniqueColumns__ = ['ciphersuite_id', 'key_size', 'post_handshake_response_id']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    ciphersuite_id = db.Column(db.Integer, db.ForeignKey('ciphers.id'))
    ciphersuite = db.relationship("CipherSuite")

    key_size = db.Column(db.Integer)

    post_handshake_response_id = db.Column(db.Integer, db.ForeignKey('c_accepted_cipher_post_handshake_response.id'))
    post_handshake_response = db.relationship("AcceptedCipherPostHandshakeResponse")

    @staticmethod
    # @functools.lru_cache(maxsize=1024)
    def from_parts(openssl_name, ssl_version, is_anonymous, key_size, post_handshake_response):
        ciphersuite_id = CipherSuite.from_parts(openssl_name, ssl_version, is_anonymous)
        post_handshake_response_id = AcceptedCipherPostHandshakeResponse.from_parts(post_handshake_response)

        return AcceptedCipherSuite.from_kwargs({"ciphersuite_id": ciphersuite_id,
                                                "post_handshake_response_id": post_handshake_response_id,
                                                "key_size": key_size})

    @staticmethod
    def from_dict(obj):
        if obj is None:
            return None
        return AcceptedCipherSuite.from_parts(obj["openssl_name"], obj["ssl_version"], obj["is_anonymous"],
                                              obj["key_size"], obj["post_handshake_response"])


class AcceptedCipherPostHandshakeResponse(Base, UniqueModel):
    __tablename__ = 'c_accepted_cipher_post_handshake_response'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)
    post_handshake_response = db.Column(db.String, unique=True)

    @staticmethod
    # @functools.lru_cache(maxsize=256)
    def from_parts(post_handshake_response):
        return AcceptedCipherPostHandshakeResponse.from_kwargs(
            {"post_handshake_response": post_handshake_response})


class RejectedCipherHandshakeErrorMessage(Base, UniqueModel):
    __tablename__ = 'c_rejected_cipher_handshake_error_message'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)
    handshake_error_message = db.Column(db.String, unique=True)

    @staticmethod  # class method here would possibly leak memory
    # @functools.lru_cache(maxsize=256)
    def from_parts(handshake_error_message):
        return RejectedCipherHandshakeErrorMessage.from_kwargs(
            {"handshake_error_message": handshake_error_message})


class TLS12SessionResumptionSupport(Base, UniqueModel):
    __tablename__ = 'tls12_session_resumption_support'
    __noUpdate__ = True
    __uniqueColumns__ = ['attempted_resumptions_nb', 'successful_resumptions_nb',
                         'errored_resumptions_list', 'failed_resumptions_nb',
                         'is_ticket_resumption_supported', 'ticket_resumption_failed_reason',
                         'ticket_resumption_error']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    attempted_resumptions_nb = db.Column(db.Integer)
    successful_resumptions_nb = db.Column(db.Integer)
    errored_resumptions_list = db.Column(db.String)  # todo: potentially deduplicate into another table
    failed_resumptions_nb = db.Column(db.Integer)
    is_ticket_resumption_supported = db.Column(db.Boolean)
    ticket_resumption_failed_reason = db.Column(db.String)
    ticket_resumption_error = db.Column(db.String)


class TLS13EarlyData(Base, UniqueModel):
    __tablename__ = 'tls13_early_data'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)

    is_early_data_supported = db.Column(db.Boolean, unique=True)


class SessionRenegotiation(Base, UniqueModel):
    __tablename__ = 'sessionrenegotiation'
    __noUpdate__ = True
    __uniqueColumns__ = ['accepts_client_renegotiation', 'supports_secure_renegotiation']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    accepts_client_renegotiation = db.Column(db.Boolean)
    supports_secure_renegotiation = db.Column(db.Boolean)


class DeflateCompression(Base, UniqueModel):
    __tablename__ = 'deflatecompression'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)

    compression_name = db.Column(db.String, unique=True)


class OpenSSLHeartbleed(Base, UniqueModel):
    __tablename__ = 'opensslheartbleed'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)

    is_vulnerable_to_heartbleed = db.Column(db.Boolean, unique=True)


class OpenSSLCCSInjection(Base, UniqueModel):
    __tablename__ = 'opensslccsinjection'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)

    is_vulnerable_to_ccs_injection = db.Column(db.Boolean, unique=True)


class DowngradeAttack(Base, UniqueModel):
    __tablename__ = 'downgradeattack'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)

    supports_fallback_scsv = db.Column(db.Boolean, unique=True)


class ROBOTAttack(Base, UniqueModel):
    __tablename__ = 'robotattack'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)

    robot_result_enum = db.Column(db.String, unique=True)


class TLS12SessionResumptionRate(Base, UniqueModel):
    __tablename__ = 'tls12_session_resumption_rate'
    __noUpdate__ = True
    __uniqueColumns__ = ['attempted_resumptions_nb', 'successful_resumptions_nb',
                         'errored_resumptions_list', 'failed_resumptions_nb']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    attempted_resumptions_nb = db.Column(db.Integer)
    successful_resumptions_nb = db.Column(db.Integer)
    errored_resumptions_list = db.Column(db.String)
    failed_resumptions_nb = db.Column(db.Integer)


class CertificateChain(Base, UniqueModel):
    __tablename__ = 'certificatechain'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)

    chain = db.Column(db.String, unique=True)

    @staticmethod
    # @functools.lru_cache(maxsize=4096)
    def from_string(chain_string):
        return CertificateChain.from_kwargs({"chain": chain_string})

    @staticmethod
    def from_list(chain):
        return CertificateChain.from_string(",".join(str(x) for x in chain))

    def not_after(self):
        return min([x.notAfter for x in Certificate.select_from_list(self.chain)])

    def not_before(self):
        return max([x.notBefore for x in Certificate.select_from_list(self.chain)])


class HTTPSecurityHeaders(Base, UniqueModel):
    __tablename__ = 'httpsecurityheaders'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)

    strict_transport_security_header = db.Column(db.String)
    public_key_pins_header = db.Column(db.String)
    public_key_pins_report_only_header = db.Column(db.String)
    expect_ct_header_max_age = db.Column(db.Integer)
    expect_ct_header_report_uri = db.Column(db.String)
    expect_ct_header_enforce = db.Column(db.Boolean)
    is_valid_pin_configured = db.Column(db.String)
    is_backup_pin_configured = db.Column(db.String)

    verified_certificate_chain_list_id = db.Column(db.Integer, db.ForeignKey('certificatechain.id'))
    verified_certificate_chain_list = db.relationship("CertificateChain")


class OCSPResponseSingle(Base, UniqueModel):
    __tablename__ = 'ocspresponse_single'
    __noUpdate__ = True
    __uniqueColumns__ = ['certID_hashAlgorithm', 'certID_issuerNameHash', 'certID_issuerKeyHash',
                         'certID_serialNumber', 'certStatus', 'thisUpdate', 'nextUpdate']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    certID_hashAlgorithm = db.Column(db.String)
    certID_issuerNameHash = db.Column(db.String)
    certID_issuerKeyHash = db.Column(db.String)
    certID_serialNumber = db.Column(db.String)
    certStatus = db.Column(db.String)
    thisUpdate = db.Column(db.DateTime)
    nextUpdate = db.Column(db.DateTime)


class OCSPResponse(Base, UniqueModel):
    __tablename__ = 'ocspresponse'
    __noUpdate__ = True
    __uniqueColumns__ = ['responseStatus', 'version', 'responseType', 'responderID', 'producedAt',
                         'responses_list']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    responseStatus = db.Column(db.String)
    version = db.Column(db.Integer)
    responseType = db.Column(db.String)
    responderID = db.Column(db.String)
    producedAt = db.Column(db.DateTime)
    responses_list = db.Column(db.String)  # future: array


class CertificateInformation(Base, UniqueModel):
    __tablename__ = 'certificateinformation'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)

    path_validation_result_list = db.Column(db.String)  # future: array
    path_validation_error_list = db.Column(db.String)

    leaf_certificate_subject_matches_hostname = db.Column(db.Boolean)
    leaf_certificate_is_ev = db.Column(db.Boolean)
    leaf_certificate_has_must_staple_extension = db.Column(db.Boolean)
    leaf_certificate_signed_certificate_timestamps_count = db.Column(db.Integer)
    received_chain_contains_anchor_certificate = db.Column(db.Boolean)
    received_chain_has_valid_order = db.Column(db.Boolean)
    verified_chain_has_sha1_signature = db.Column(db.Boolean)
    verified_chain_has_legacy_symantec_anchor = db.Column(db.Boolean)

    ocsp_response_id = db.Column(db.Integer, db.ForeignKey('ocspresponse.id'))
    ocsp_response = db.relationship("OCSPResponse")

    ocsp_response_status = db.Column(db.String)
    ocsp_response_is_trusted = db.Column(db.Boolean)

    # todo: this is named list but it seems I'm only using it as single cert chain. Check!!!
    received_certificate_chain_list_id = db.Column(db.Integer, db.ForeignKey('certificatechain.id'))
    received_certificate_chain_list = db.relationship("CertificateChain",
                                                      foreign_keys=[received_certificate_chain_list_id])

    # todo: this is named list but it seems I'm only using it as single cert chain. Check!!!
    verified_certificate_chain_list_id = db.Column(db.Integer, db.ForeignKey('certificatechain.id'))
    verified_certificate_chain_list = db.relationship("CertificateChain",
                                                      foreign_keys=[verified_certificate_chain_list_id])


class ValidatedPath(Base, UniqueModel):
    __tablename__ = 'validatedpaths'
    __noUpdate__ = True
    __uniqueColumns__ = ['trust_store_id', 'chain_id', 'verify_string']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    trust_store_id = db.Column(db.Integer, db.ForeignKey('truststores.id'))
    trust_store = db.relationship("TrustStore")

    chain_id = db.Column(db.Integer, db.ForeignKey('certificatechain.id'))
    chain = db.relationship("CertificateChain")

    verify_string = db.Column(db.String)


class ScanResults(Base, UniqueModel):
    __tablename__ = 'scanresults'
    __noUpdate__ = True

    id = db.Column(db.Integer, primary_key=True)

    server_info_id = db.Column(db.Integer, db.ForeignKey('serverinfos.id'))
    deflate_compression_id = db.Column(db.Integer, db.ForeignKey('deflatecompression.id'))
    session_renegotiation_id = db.Column(db.Integer, db.ForeignKey('sessionrenegotiation.id'))
    tls_13_early_data_id = db.Column(db.Integer, db.ForeignKey('tls13_early_data.id'))
    openssl_ccs_injection_id = db.Column(db.Integer, db.ForeignKey('opensslccsinjection.id'))
    openssl_heartbleed_id = db.Column(db.Integer, db.ForeignKey('opensslheartbleed.id'))
    downgrade_attacks_id = db.Column(db.Integer, db.ForeignKey('downgradeattack.id'))
    robot_attack_id = db.Column(db.Integer, db.ForeignKey('robotattack.id'))
    tls_12_session_resumption_rate_id = db.Column(db.Integer, db.ForeignKey('tls12_session_resumption_rate.id'))
    tls_12_session_resumption_support_id = db.Column(db.Integer, db.ForeignKey('tls12_session_resumption_support.id'))
    http_security_headers_id = db.Column(db.Integer, db.ForeignKey('httpsecurityheaders.id'))
    certificate_information_id = db.Column(db.Integer, db.ForeignKey('certificateinformation.id'))
    sslv2_id = db.Column(db.Integer, db.ForeignKey('ciphersuitescanresults.id'))
    sslv3_id = db.Column(db.Integer, db.ForeignKey('ciphersuitescanresults.id'))
    tlsv1_id = db.Column(db.Integer, db.ForeignKey('ciphersuitescanresults.id'))
    tlsv11_id = db.Column(db.Integer, db.ForeignKey('ciphersuitescanresults.id'))
    tlsv12_id = db.Column(db.Integer, db.ForeignKey('ciphersuitescanresults.id'))
    tlsv13_id = db.Column(db.Integer, db.ForeignKey('ciphersuitescanresults.id'))

    server_info = db.relationship("ServerInfo", lazy='joined')
    deflate_compression = db.relationship("DeflateCompression")
    session_renegotiation = db.relationship("SessionRenegotiation")
    tls_13_early_data = db.relationship("TLS13EarlyData")
    openssl_ccs_injection = db.relationship("OpenSSLCCSInjection")
    openssl_heartbleed = db.relationship("OpenSSLHeartbleed")
    downgrade_attacks = db.relationship("DowngradeAttack")
    robot_attack = db.relationship("ROBOTAttack")
    tls_12_session_resumption_rate = db.relationship("TLS12SessionResumptionRate")
    tls_12_session_resumption_support = db.relationship("TLS12SessionResumptionSupport")
    http_security_headers = db.relationship("HTTPSecurityHeaders")
    certificate_information = db.relationship("CertificateInformation")
    sslv2 = db.relationship("CipherSuiteScanResult", foreign_keys=[sslv2_id])
    sslv3 = db.relationship("CipherSuiteScanResult", foreign_keys=[sslv3_id])
    tlsv1 = db.relationship("CipherSuiteScanResult", foreign_keys=[tlsv1_id])
    tlsv11 = db.relationship("CipherSuiteScanResult", foreign_keys=[tlsv11_id])
    tlsv12 = db.relationship("CipherSuiteScanResult", foreign_keys=[tlsv12_id])
    tlsv13 = db.relationship("CipherSuiteScanResult", foreign_keys=[tlsv13_id])


class ScanResultsHistory(Base, UniqueModel):
    __tablename__ = 'scanresultshistory'
    __uniqueColumns__ = ['target_id', 'scanresult_id']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(NumericTimestamp, default=datetime_to_timestamp(datetime.datetime.now()))

    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=False)
    target = db.relationship("Target")

    scanresult_id = db.Column(db.Integer, db.ForeignKey('scanresults.id'), nullable=False)
    scanresult = db.relationship("ScanResults")


class SentNotificationsLog(Base, UniqueModel):
    __tablename__ = 'notificationssentlog'
    __uniqueColumns__ = ['sent_notification_id', 'channel']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(NumericTimestamp, default=datetime_to_timestamp(datetime.datetime.now()))

    sent_notification_id = db.Column(db.String, nullable=False)
    channel = db.Column(db.String, nullable=False)


class ScanResultsSimplified(Base, UniqueModel):
    __tablename__ = 'scanresultssimplified'
    __uniqueColumns__ = ['scanresult_id']

    id = db.Column(db.Integer, primary_key=True)  # This id might not be the same as scanresult_id. # todo: fix

    scanresult_id = db.Column(db.Integer,
                              index=True)  # This is needed because Marshmallow in my conf throws away id param.

    notBefore = db.Column(NumericTimestamp)
    notAfter = db.Column(NumericTimestamp)
    grade = db.Column(db.String)
    grade_reasons = db.Column(db.String)

    received_certificate_chain_list_id = db.Column(db.Integer, db.ForeignKey('certificatechain.id'))
    received_certificate_chain_list = db.relationship("CertificateChain",
                                                      foreign_keys=[received_certificate_chain_list_id])

    verified_certificate_chains_lists_ids = db.Column(db.String)

    validated_against_truststores_list = db.Column(db.String)

    sslv2_working_ciphers_count = db.Column(db.Integer)
    sslv2_working_weak_ciphers_count = db.Column(db.Integer)

    sslv3_working_ciphers_count = db.Column(db.Integer)
    sslv3_working_weak_ciphers_count = db.Column(db.Integer)

    tlsv10_working_ciphers_count = db.Column(db.Integer)
    tlsv10_working_weak_ciphers_count = db.Column(db.Integer)

    tlsv11_working_ciphers_count = db.Column(db.Integer)
    tlsv11_working_weak_ciphers_count = db.Column(db.Integer)

    tlsv12_working_ciphers_count = db.Column(db.Integer)
    tlsv12_working_weak_ciphers_count = db.Column(db.Integer)

    tlsv13_working_ciphers_count = db.Column(db.Integer)
    tlsv13_working_weak_ciphers_count = db.Column(db.Integer)


class SlackConnections(Base, UniqueModel):
    __tablename__ = 'slackconnections'
    __uniqueColumns__ = ['user_id', 'channel_id', 'team_id']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship("User")

    channel_id = db.Column(db.String)
    channel_name = db.Column(db.String)

    team_id = db.Column(db.String)
    team_name = db.Column(db.String)

    access_token = db.Column(db.String)
    webhook_url = db.Column(db.String)

    def __str__(self):
        return f"{self.user_id}, {self.channel_name}"

    def as_dict(self):
        return {'id': self.id,
                'channel_id': self.channel_id,
                'channel_name': self.channel_name,
                'team_id': self.team_id,
                'team_name': self.team_name,
                }


class TmpRandomCodes(Base, UniqueModel):
    __tablename__ = 'tmprandomcodes'
    __uniqueColumns__ = ['code']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(NumericTimestamp, default=datetime_to_timestamp(datetime.datetime.now()))
    expires = db.Column(NumericTimestamp)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship("User")

    code = db.Column(db.String, unique=True, index=True)
    activity = db.Column(db.String)

    params = db.Column(db.String)


class MailConnections(Base, UniqueModel):
    __tablename__ = 'mailconnections'
    __uniqueColumns__ = ['user_id', 'email']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship("User")

    email = db.Column(db.String)
    validated = db.Column(db.Boolean, default=False)

    def __str__(self):
        return f"{self.email}, {self.validated}"

    def as_dict(self):
        return {'id': self.id,
                'email': self.email,
                'validated': self.validated,
                }


class ConnectionStatusOverrides(Base, UniqueModel):
    __tablename__ = 'connectionstatusoverrides'
    __uniqueColumns__ = ['user_id', 'target_id']
    __table_args__ = (db.UniqueConstraint(*__uniqueColumns__, name=f'_uq_{__tablename__}'),)

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship("User")

    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=True)
    target = db.relationship("Target")

    preferences = db.Column(db.JSON)

    # Example of preference JSON
    """
    {
        "email": {
            "force_disable": false,
            "force_enabled_ids": [1, 2, 10], # Force enabled can't override force_disabled
            "force_disabled_ids": [4, 20, 30],
            "add_new_emails": ["test1@example.com", "test2@example.com"]
                // This should only appear in new request, not in DB.
                // If emails don't exist, they are created and IDs will be added to force_enabled_ids.
                // If emails do exist, their IDs will be added to force_enabled_ids.
                  
        },
        "slack": {
            "force_disable": false,
            "force_enabled_ids": [1, 2, 10], # Force enabled can't override force_disabled
            "force_disabled_ids": [4, 20, 30], 
        }
    }
    """


# This might not yet work properly. todo: fix it
class PlainTextNotification(Base):
    # This will be used for notifications in UI and RSS.
    __tablename__ = 'plaintextnotifications'

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True)
    user = db.relationship("User")

    target_id = db.Column(db.Integer, db.ForeignKey('targets.id'), nullable=True)
    target = db.relationship("Target")

    channel = db.Column(db.String, default="all")

    event_id = db.Column(db.String)
    notification_id = db.Column(db.String, unique=True)  # notification_id should be globally unique, not only in channel
    msg = db.Column(db.JSON)

