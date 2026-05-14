class DeltaDbError(Exception):
    pass


class LoaderError(DeltaDbError):
    pass


class DatabaseConnectionError(LoaderError):
    pass


class DatabaseReflectionError(LoaderError):
    pass


class SecurityError(DeltaDbError):
    pass


class DiffError(DeltaDbError):
    pass


class CircularDependencyError(DiffError):
    pass


class GeneratorError(DeltaDbError):
    pass


class TemplateRenderError(GeneratorError):
    pass
