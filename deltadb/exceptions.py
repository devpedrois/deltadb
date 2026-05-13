class DeltaDbError(Exception):
    pass


class LoaderError(DeltaDbError):
    pass


class SecurityError(DeltaDbError):
    pass


class DiffError(DeltaDbError):
    pass


class GeneratorError(DeltaDbError):
    pass
