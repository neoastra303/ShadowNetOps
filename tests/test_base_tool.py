import pytest
from tools.base_tool import BaseTool, URL_PATTERN, DOMAIN_PATTERN, IP_PATTERN, DANGEROUS_CHARS


class TestPatterns:
    def test_url_pattern_valid(self):
        assert URL_PATTERN.match("http://example.com")
        assert URL_PATTERN.match("https://example.com/path?query=1")
        assert URL_PATTERN.match("https://192.168.1.1:8080")
        assert URL_PATTERN.match("http://localhost:3000")

    def test_url_pattern_invalid(self):
        assert not URL_PATTERN.match("not-a-url")
        assert not URL_PATTERN.match("ftp://example.com")
        assert not URL_PATTERN.match("")

    def test_domain_pattern_valid(self):
        assert DOMAIN_PATTERN.match("example.com")
        assert DOMAIN_PATTERN.match("sub.domain.co.uk")
        assert DOMAIN_PATTERN.match("localhost")

    def test_domain_pattern_invalid(self):
        assert not DOMAIN_PATTERN.match("")
        assert not DOMAIN_PATTERN.match(";;;")
        assert not DOMAIN_PATTERN.match("example.com;rm -rf /")

    def test_ip_pattern_valid(self):
        assert IP_PATTERN.match("192.168.1.1")
        assert IP_PATTERN.match("10.0.0.0/24")
        assert IP_PATTERN.match("8.8.8.8")

    def test_ip_pattern_invalid(self):
        assert not IP_PATTERN.match("not-an-ip")
        assert not IP_PATTERN.match("")
        assert not IP_PATTERN.match("....")
        assert not IP_PATTERN.match("a.b.c.d")


class TestBaseTool:
    def test_validate_input_safe(self, console):
        tool = DummyTool(console)
        assert tool.validate_input("hello")
        assert tool.validate_input("example.com")
        assert tool.validate_input("192.168.1.1")

    def test_validate_input_dangerous(self, console):
        tool = DummyTool(console)
        assert not tool.validate_input("hello; rm -rf /")
        assert not tool.validate_input("x || y")
        assert not tool.validate_input("$(cat /etc/passwd)")

    def test_validate_url(self, console):
        assert BaseTool.validate_url("http://example.com")
        assert BaseTool.validate_url("https://example.com:443/path")
        assert not BaseTool.validate_url("javascript:alert(1)")
        assert not BaseTool.validate_url("")

    def test_validate_domain(self, console):
        assert BaseTool.validate_domain("example.com")
        assert BaseTool.validate_domain("sub.example.co.uk")
        assert not BaseTool.validate_domain("")
        assert not BaseTool.validate_domain(";;;")

    def test_validate_target(self, console):
        assert BaseTool.validate_target("192.168.1.1")
        assert BaseTool.validate_target("example.com")
        assert not BaseTool.validate_target("192.168.1.1; rm -rf")
        assert not BaseTool.validate_target("")


class DummyTool(BaseTool):
    def run(self):
        pass