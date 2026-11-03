import hashlib,json,pathlib,struct,sys

def exec_data(data):
    assert data[:5] == bytes.fromhex("01c0c01007"), "First/unique supported header required"
    pos = 0

    def take(n):
        nonlocal pos
        out = data[pos:pos+n]
        assert len(out) == n
        pos += n
        return out

    def utf():
        return take(struct.unpack(">H", take(2))[0]).decode("utf-8")

    sessions, names, headers = [], [], 0
    while pos < len(data):
        block = take(1)[0]
        if block == 1:
            assert take(4) == bytes.fromhex("c0c01007")
            headers += 1
        elif block == 16:
            sessions.append((utf(), *struct.unpack(">QQ", take(16))))
        elif block == 17:
            take(8)
            names.append(utf())
            n, shift = 0, 0
            while True:
                v = take(1)[0]
                n |= (v & 127) << shift
                if not v & 128:
                    break
                shift += 7
            take((n+7)//8)
        else:
            raise AssertionError(("unknown exec block", block))
    assert headers == len(sessions) == 1
    assert len(names) == len(set(names)) and names
    return {"session": sessions[0], "records": len(names),
            "externalRecords": sum(not n.startswith("org/springframework/samples/petclinic/") for n in names)}

def read_exec(path, arm):
    assert arm in ("default", "candidate"), "Known arm required"
    source = pathlib.Path(path).resolve(strict=True)
    data = source.read_bytes()
    value = exec_data(data)
    assert value["records"] > value["externalRecords"]
    assert value["externalRecords"] == 0 if arm == "candidate" else value["externalRecords"] > 0
    value["sha256"] = hashlib.sha256(data).hexdigest().upper()
    value["source"] = str(source)
    return value

if __name__ == "__main__":
    pathlib.Path(sys.argv[3]).write_text(json.dumps(read_exec(sys.argv[1], sys.argv[2]), indent=2))
