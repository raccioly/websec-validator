"""Shared temp-repo helper for the #241–#248 regression tests (synthetic `acme` fixtures only)."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from websec_validator.extractors import run_all  # noqa: E402
from websec_validator.findings import build_ledger  # noqa: E402

SPRING_POM = """<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
  <groupId>com.acme</groupId><artifactId>{artifact}</artifactId><version>1.0.0</version>
  <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.3.5</version></parent>
  <dependencies>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
    <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-jdbc</artifactId></dependency>
    {extra}
  </dependencies>
</project>
"""
SECURITY_DEP = ("<dependency><groupId>org.springframework.boot</groupId>"
                "<artifactId>spring-boot-starter-oauth2-resource-server</artifactId></dependency>")


class TempRepo(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name)

    def tearDown(self):
        self._dir.cleanup()

    def write(self, rel, text):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def pom(self, rel="pom.xml", artifact="svc", extra=""):
        self.write(rel, SPRING_POM.format(artifact=artifact, extra=extra))

    def facts(self, **kwargs):
        return run_all(self.root, "t", **kwargs)

    def ledger(self, facts=None):
        return build_ledger(facts or self.facts(), None)["findings"]

    def kinds(self, attack_class, facts=None):
        return [(f["severity"], f.get("title"), f.get("location"))
                for f in self.ledger(facts) if f.get("attack_class") == attack_class]
