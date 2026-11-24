import json

import pytest

from scam_lens import (
    LIKELY_SCAM,
    NO_KNOWN_RED_FLAGS,
    SUSPICIOUS,
    analyze,
    list_packs,
    load_pack,
)
from scam_lens.cli import main
from scam_lens.urls import find_urls, host_of


def ids(report):
    return {f.rule_id for f in report.findings}


def test_empty_message_has_no_red_flags():
    report = analyze("")
    assert report.verdict == NO_KNOWN_RED_FLAGS
    assert report.findings == []
    assert report.score == 0


def test_ordinary_message_has_no_red_flags():
    report = analyze("Hey, are we still meeting for lunch at 1pm tomorrow?")
    assert report.verdict == NO_KNOWN_RED_FLAGS


def test_there_is_no_safe_verdict():
    # The tool must never claim a message is safe.
    for text in ["", "hello", "Urgent: send your OTP to http://bit.ly/x"]:
        assert "SAFE" not in analyze(text).verdict.replace("UNSAFE", "").split("_")


def test_legitimate_otp_notice_is_not_flagged():
    report = analyze("Your OTP is 482913. Do not share it with anyone.")
    assert "credential-request" not in ids(report)
    assert report.verdict == NO_KNOWN_RED_FLAGS


def test_never_share_wording_is_not_flagged():
    report = analyze("Never share your PIN or password with anyone, including bank staff.")
    assert "credential-request" not in ids(report)


def test_asking_for_otp_is_high_severity():
    report = analyze("Please reply with your OTP to confirm the payment.")
    assert "credential-request" in ids(report)
    assert report.verdict == SUSPICIOUS or report.verdict == LIKELY_SCAM
    finding = next(f for f in report.findings if f.rule_id == "credential-request")
    assert finding.severity == "high"


def test_prize_message_with_shortener_is_likely_scam():
    report = analyze("Congratulations! You have won a prize. Claim your reward now: http://bit.ly/abc123")
    assert {"prize", "link-shortener"} <= ids(report)
    assert report.verdict == LIKELY_SCAM


def test_lookalike_brand_domain_is_flagged():
    report = analyze("PayPal: your account is suspended. Verify at https://paypal-secure-login.example.com/verify")
    assert "lookalike-paypal" in ids(report)
    assert report.verdict == LIKELY_SCAM


def test_official_brand_domain_is_not_flagged():
    report = analyze("Your PayPal receipt is available at https://www.paypal.com/activity")
    assert not any(i.startswith(("lookalike-", "brand-mismatch-")) for i in ids(report))


def test_brand_mentioned_but_link_elsewhere():
    report = analyze("Your Amazon order has shipped, track it here: https://track-parcels.example.org/id/991")
    assert "brand-mismatch-amazon" in ids(report)


def test_ip_address_link():
    report = analyze("Log in at http://203.0.113.9/bank/login")
    assert "link-ip-address" in ids(report)


def test_userinfo_trick_in_link():
    report = analyze("Open https://mybank.com@evil.example.net/login")
    assert "link-userinfo" in ids(report)
    assert host_of("https://mybank.com@evil.example.net/login") == "evil.example.net"


def test_punycode_link():
    report = analyze("Visit https://xn--pypal-4ve.com/login")
    assert "link-punycode" in ids(report)


def test_each_rule_counts_once():
    once = analyze("Urgent!")
    many = analyze("Urgent! Urgent! Urgent! Act now, immediately!")
    assert once.score == many.score


def test_find_urls_strips_trailing_punctuation_and_dedupes():
    urls = find_urls("See https://example.com/a. Also https://example.com/a, and bit.ly/xyz!")
    assert urls == ["https://example.com/a", "bit.ly/xyz"]


def test_family_impersonation():
    report = analyze("Hi mum, I lost my phone, this is my new number. Can you pay a bill for me?")
    assert "family-impersonation" in ids(report)


def test_bundled_packs_load_and_validate():
    assert {"global", "pk"} <= set(list_packs())
    for name in list_packs():
        pack = load_pack(name)
        assert pack.name == name
        assert all(rule.weight in (1, 2, 3) for rule in pack.rules)


def test_pk_pack_adds_regional_rules():
    text = "Your SIM will be blocked today. Verify with your CNIC now."
    base = analyze(text)
    regional = analyze(text, [load_pack("global"), load_pack("pk")])
    assert "pk-sim-block" in ids(regional)
    assert "pk-sim-block" not in ids(base)


def test_unknown_pack_is_rejected():
    with pytest.raises(ValueError):
        load_pack("does-not-exist")


def test_pack_name_cannot_escape_the_folder():
    with pytest.raises(ValueError):
        load_pack("../secrets")


def test_cli_exit_codes_and_json(capsys):
    assert main(["Lunch at 1pm?"]) == 0
    capsys.readouterr()
    code = main(["--json", "Congratulations you have won! Send your OTP now: http://bit.ly/q"])
    assert code == 2
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == LIKELY_SCAM
    assert data["findings"]


def test_cli_reports_bad_pack(capsys):
    assert main(["-p", "nope", "hello"]) == 64
    assert "unknown pack" in capsys.readouterr().err
