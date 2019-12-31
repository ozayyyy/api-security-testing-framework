from apistf.cli import build_parser


def test_parser_defaults():
    args = build_parser().parse_args([])
    assert args.target == "http://127.0.0.1:8000"
    assert args.prefix == "/vuln"
    assert args.format == "json"
    assert args.budget == 500


def test_parser_overrides():
    args = build_parser().parse_args(
        ["--target", "http://127.0.0.1:8001", "--prefix", "/secure",
         "--detectors", "bola,jwt", "--format", "md"])
    assert args.target == "http://127.0.0.1:8001"
    assert args.prefix == "/secure"
    assert args.detectors == "bola,jwt"
    assert args.format == "md"
