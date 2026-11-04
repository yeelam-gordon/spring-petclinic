"""Small contract models only: no compiled classes, real dependencies or runtime evidence."""
import argparse
import copy
import hashlib
import json
import pathlib
import shutil
import struct
import subprocess
import zipfile

PIN = "6feeae0f13e0e258eedc99832416b42bb13779b1"
def make(git, repository, output):
    root = pathlib.Path(output)
    root.mkdir(parents=True, exist_ok=False)
    def save(name, value):
        (root / name).write_text(json.dumps(value, indent=2)+"\n", encoding="utf-8")
    def blob(name):
        return subprocess.check_output([git, "-C", repository, "show", PIN+":"+name])
    pom = blob("pom.xml")
    assert hashlib.sha256(pom).hexdigest().upper() == "A41D9CC2B0287AA03BCE5205171B111FD1620A4DD6DCF48D9624A189B50F1E0D"
    pins = []
    for name in ["pom.xml", ".mvn/jvm.config", ".gitattributes", "mvnw", "mvnw.cmd", ".mvn/wrapper/maven-wrapper.properties"]:
        value = blob(name)
        pins.append({"path": name, "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest().upper()})
    save("committed-input-pins.json", pins)
    refs = [f"SYNTHETIC-component-{i}" for i in range(108)]
    bom = {"metadata": {"component": {"bom-ref": "SYNTHETIC-root"}},
           "components": [{"bom-ref": ref, "type": "library", "name": ref, "version": "NOT-A-REAL-DEPENDENCY"} for ref in refs],
           "dependencies": [{"ref": ref, "dependsOn": []} for ref in ["SYNTHETIC-root"]+refs]}
    base = {
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\nImplementation-Title: SYNTHETIC-PARSER-MODEL\r\nSbom-Location: META-INF/sbom/application.cdx.json\r\nSbom-Format: CycloneDX\r\n\r\n",
        "META-INF/build-info.properties": b"build.version=SYNTHETIC-NOT-A-BUILD\n",
        "META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml": pom,
        "META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties": b"version=SYNTHETIC-NOT-A-BUILD\n",
    }
    for i in range(30):
        base[f"BOOT-INF/classes/org/springframework/samples/petclinic/Model{i}.class"] = bytes.fromhex("CAFEBABE0000003D")+f"NOT-COMPILED-{i}".encode()
    for i in range(98):
        base[f"BOOT-INF/lib/SYNTHETIC-{i}.jar"] = f"NOT-A-JAR-DEPENDENCY-{i}".encode()
    for i in range(151):
        base[f"BOOT-INF/classes/model-resources/resource{i}.txt"] = b"SYNTHETIC"
    dirs = ["META-INF/", "META-INF/sbom/", "BOOT-INF/", "BOOT-INF/classes/", "BOOT-INF/lib/"]+[f"SYNTHETIC-directory-{i}/" for i in range(45)]
    def payload(dirty, offline=False, altered_bom=None):
        entries = {name: b"" for name in dirs}
        entries.update(base)
        entries["BOOT-INF/classes/git.properties"] = f"git.commit.id={PIN}\ngit.dirty={'true' if dirty else 'false'}\nfixture.provenance=SYNTHETIC-NOT-A-BUILD\n".encode()
        entries["META-INF/sbom/application.cdx.json"] = json.dumps(altered_bom or bom, separators=(",", ":")).encode()
        if offline:
            del entries["META-INF/sbom/"]
            del entries["META-INF/sbom/application.cdx.json"]
            entries["META-INF/MANIFEST.MF"] = entries["META-INF/MANIFEST.MF"].replace(b"Sbom-Location: META-INF/sbom/application.cdx.json\r\n", b"").replace(b"Sbom-Format: CycloneDX\r\n", b"")
        assert len(entries) == (333 if offline else 335)
        assert sum(not n.endswith("/") for n in entries) == (284 if offline else 285)
        return entries
    def archive(path, entries):
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for name, value in entries.items():
                z.writestr(name, value)
    home = "SYNTHETIC-JDK-NOT-INSTALLED"
    def project(path, dirty, offline=False):
        target = path / "target"
        for folder in ["classes", "test-classes", "surefire-reports", "site/jacoco"]:
            target.joinpath(*folder.split("/")).mkdir(parents=True, exist_ok=True)
        entries = payload(dirty, offline)
        archive(target / "application.jar", entries)
        for name, value in entries.items():
            if name.startswith("BOOT-INF/classes/") and not name.endswith("/"):
                p = target / "classes" / pathlib.Path(*pathlib.PurePosixPath(name).parts[2:])
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(value)
        if not offline:
            p = target / "classes" / "META-INF" / "sbom" / "application.cdx.json"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(entries["META-INF/sbom/application.cdx.json"])
        for i in range(25):
            (target / "test-classes" / f"ModelTest{i}.class").write_bytes(bytes.fromhex("CAFEBABE0000003D")+b"NOT-COMPILED")
        import xml.sax.saxutils as sax
        props = "".join(f'<property name="{k}" value="{sax.escape(v, {chr(34): "&quot;"})}"/>' for k, v in [
            ("java.home", home), ("java.runtime.version", "25.0.5.0.2+1-LTS"), ("java.vendor", "Microsoft"), ("os.arch", "aarch64")])
        tests = "".join(f'<testcase classname="SYNTHETIC" name="model{i}">{ "<skipped/>" if i >= 54 else ""}</testcase>' for i in range(56))
        (target / "surefire-reports" / "TEST-synthetic.xml").write_text(f"<testsuite><properties>{props}</properties>{tests}</testsuite>", encoding="utf-8")
        counters = "".join(f'<method name="model{i}" desc="()V">'+"".join(f'<counter type="{t}" missed="0" covered="1"/>' for t in ["INSTRUCTION","BRANCH","LINE","COMPLEXITY","METHOD","CLASS"])+"</method>" for i in range(121))
        classes = '<class name="org/springframework/samples/petclinic/Model0">'+counters+'</class>'+"".join(f'<class name="org/springframework/samples/petclinic/Model{i}"/>' for i in range(1,25))
        lines = "".join(f'<line nr="{i}" mi="0" ci="1"/>' for i in range(1,297))
        (target / "site" / "jacoco" / "jacoco.xml").write_text(f'<report name="SYNTHETIC"><sessioninfo id="s" start="1" dump="2"/><package name="synthetic">{classes}<sourcefile name="Model.java">{lines}</sourcefile></package></report>', encoding="utf-8")
        # Same tiny0x1007 encoding pattern as the public JacocoExecFixture; not coverage.
        exe = bytearray.fromhex("01C0C010071000017300000000000000010000000000000002")
        for i, name in enumerate(["org/springframework/samples/petclinic/Model0", "org/synthetic/ExternalModel"], 1):
            value = name.encode()
            exe.extend(b"\x11"+struct.pack(">qH", i, len(value))+value+b"\x01\x01")
        (target / "jacoco.exec").write_bytes(exe)
        return target
    clean = project(root / "clean", False)
    reviewed = root / "reviewed"
    dirty = project(reviewed / "online", True)
    project(reviewed / "offline", True, True)
    clean_off = project(root / "clean-offline", False, True)
    save("fixture-provenance.json", {"project": str(clean.parent), "label": "SYNTHETIC-CLEAN-NOT-HISTORICAL"})
    save("screen-fixture.json", {"root": str(reviewed), "actualDirtyDonor": str(dirty / "application.jar"), "synthetic": True,
         "provenance": "SYNTHETIC-ONLY; actualDirtyDonor is a legacy parameter name, not actual build evidence"})
    mutations = []
    for case in ["missing-role", "bad-graph", "unknown-entry", "wrong-pom"]:
        entries = payload(False)
        if case == "missing-role": del entries["META-INF/maven/org.springframework.samples/spring-petclinic/pom.properties"]
        if case == "bad-graph":
            value = copy.deepcopy(bom); value["dependencies"][0]["dependsOn"] = ["UNREVIEWED_NODE"]
            entries["META-INF/sbom/application.cdx.json"] = json.dumps(value).encode()
        if case == "unknown-entry": entries["UNREVIEWED.txt"] = b"SYNTHETIC"
        if case == "wrong-pom": entries["META-INF/maven/org.springframework.samples/spring-petclinic/pom.xml"] += b"\n<!-- SYNTHETIC WRONG POM -->"
        path = root / f"{case}.jar"; archive(path, entries); mutations.append({"case": case, "path": str(path)})
    save("fidelity-inputs.json", mutations)
    deep = copy.deepcopy(bom); node = {"value": "SYNTHETIC_DEEP_VALUE"}
    for _ in range(24): node = {"next": node}
    deep["dependencies"][0]["extension"] = node
    deep_path = root / "deep.jar"; archive(deep_path, payload(True, altered_bom=deep))
    (root / "deep-jar-path.txt").write_text(str(deep_path), encoding="utf-8")
    result = {"readiness": str(root), "cleanCapture": str(clean), "cleanOfflineProject": str(clean_off),
              "synthetic": True, "javaExecuted": False, "compiledJava": False, "realDependencies": False,
              "scope": "Parser/schema/count/binding models only; no coverage/runtime/performance proof"}
    save("fixture-inputs.json", result)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--git", required=True); p.add_argument("--repository", required=True); p.add_argument("--output", required=True)
    args = p.parse_args()
    make(args.git, args.repository, args.output)
