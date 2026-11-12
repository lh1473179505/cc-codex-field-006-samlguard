class SamlguardError(Exception):
    """Base error."""


class FormatError(SamlguardError):
    pass


class CryptoError(SamlguardError):
    pass


class NotImplementedVerify(SamlguardError):
    pass
