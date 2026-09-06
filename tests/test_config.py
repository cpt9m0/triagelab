from triagelab import config


def test_load_env_parses_pairs_comments_and_quotes(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "# a comment\n"
        "\n"
        "VT_API_KEY=abc123\n"
        'QUOTED="with quotes"\n'
        "INLINE=value # trailing comment\n"
        "NOT_A_PAIR\n",
        encoding="utf-8",
    )
    values = config.load_env(env)
    assert values["VT_API_KEY"] == "abc123"
    assert values["QUOTED"] == "with quotes"
    assert values["INLINE"] == "value"
    assert "NOT_A_PAIR" not in values


def test_load_env_returns_empty_when_file_missing(tmp_path):
    assert config.load_env(tmp_path / "nope.env") == {}


def test_real_environment_wins_over_dotenv(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "from-environment")
    assert config.get("VT_API_KEY") == "from-environment"


def test_placeholder_key_is_treated_as_unset(monkeypatch):
    monkeypatch.setattr(config, "get", lambda key, default=None: "your-key-here")
    assert config.vt_api_key() is None
