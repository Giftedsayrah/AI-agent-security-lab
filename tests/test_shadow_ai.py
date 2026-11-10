"""Shadow AI discovery must match services on domain boundaries and read common log shapes."""
import shadow_ai as sa


def test_domain_matching_respects_boundaries():
    assert sa.match_service("api.openai.com")[0] == "OpenAI / ChatGPT"
    assert sa.match_service("claude.ai")[0] == "Anthropic / Claude"
    assert sa.match_service("notopenai.com") is None
    assert sa.match_service("box.ai") is None
    assert sa.to_host("https://chatgpt.com/c/123?x=1") == "chatgpt.com"
    assert sa.to_host("API.OpenAI.com:443") == "api.openai.com"


def test_csv_export_counts_requests_users_and_allowed_status(tmp_path):
    log = tmp_path / "proxy.csv"
    log.write_text("timestamp,username,cs-host\n"
                   "2026-11-01T09:00,ada,chatgpt.com\n2026-11-01T09:01,ada,chatgpt.com\n"
                   "2026-11-01T09:02,bola,api.openai.com\n2026-11-01T09:03,bola,intranet.acme.example\n"
                   "2026-11-01T09:04,chidi,copilot.microsoft.com\n")
    result = sa.analyse(sa.read_rows(log), allowed=["Microsoft Copilot"])
    assert result["total"] == 5
    openai = result["services"]["OpenAI / ChatGPT"]
    assert openai["requests"] == 3 and openai["users"] == {"ada", "bola"} and openai["status"] == "SHADOW AI"
    assert result["services"]["Microsoft Copilot"]["status"] == "allowed"
    report = sa.build_report(result, "proxy.csv")
    assert "| OpenAI / ChatGPT | 3 | 2 |" in report and "sections 41 and 42" in report


def test_plain_text_logs_and_urls_are_scanned(tmp_path):
    log = tmp_path / "dns.log"
    log.write_text("Nov  1 09:00:01 query: claude.ai A from 10.0.0.5\n"
                   "Nov  1 09:00:02 query: www.example.org A from 10.0.0.6\n"
                   "Nov  1 09:00:03 query: generativelanguage.googleapis.com A from 10.0.0.5\n")
    result = sa.analyse(sa.read_rows(log))
    assert set(result["services"]) == {"Anthropic / Claude", "Google Gemini"}

    urls = tmp_path / "urls.tsv"
    urls.write_text("time\tsrc_ip\turl\n9:00\t10.0.0.5\thttps://perplexity.ai/search?q=x\n")
    found = sa.analyse(sa.read_rows(urls))["services"]["Perplexity"]
    assert found["users"] == {"10.0.0.5"}


def test_empty_result_and_column_override(tmp_path):
    log = tmp_path / "x.csv"
    log.write_text("when,who,site\n1,ada,example.org\n")
    assert "No known AI services" in sa.build_report(sa.analyse(sa.read_rows(log, "site", "who")), "x.csv")
