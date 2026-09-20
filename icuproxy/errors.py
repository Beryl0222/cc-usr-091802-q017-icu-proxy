"""领域错误类型，服务层抛出，HTTP 层映射为状态码。"""


class DomainError(Exception):
    """所有领域错误的基类。"""

    status = 400


class ValidationError(DomainError):
    """入参或状态不满足领域约束。"""

    status = 422


class NotFoundError(DomainError):
    """请求的对象不存在（或对请求者不可见）。"""

    status = 404


class ConflictStateError(DomainError):
    """当前状态下不允许该操作（含幂等冲突）。"""

    status = 409


class StaleVersionError(DomainError):
    """基于过时快照执行确认等操作。"""

    status = 409


class PermissionDenied(DomainError):
    """当前操作者无权执行该操作或查看该数据。"""

    status = 403
