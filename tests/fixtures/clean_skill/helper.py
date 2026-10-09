"""安全 skill 样例脚本（用于验证 skill_scan 不误报）。

仅做纯文本处理，无任何命令执行 / 网络 / 文件写 / 反序列化。
"""
def greet(name: str) -> str:
    return f"Hello, {name}!"


def format_text(text: str) -> str:
    return text.strip().capitalize()
