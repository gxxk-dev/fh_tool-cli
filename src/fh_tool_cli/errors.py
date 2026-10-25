from __future__ import annotations


class CliError(RuntimeError):
    pass


class FHToolError(RuntimeError):
    pass


class FHToolHttpError(FHToolError):
    """fh_tool/api 返回了非 200 状态码。"""

    def __init__(self, message: str, *, status_code: int) -> None:
        super().__init__(message)
        self.status_code = status_code


class FHToolResponseError(FHToolError):
    """fh_tool/api 返回 200,但响应体不是当前 MAC 可解密的 fh_tool 密文。

    携带响应体分类而不是原文:明文 JSON 响应可能包含 adminpwd 等敏感值,
    只用于诊断“这个端口/路径到底是不是 fh_tool API”。
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        content_type: str | None,
        body_kind: str,
        body_length: int,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.content_type = content_type
        self.body_kind = body_kind
        self.body_length = body_length
