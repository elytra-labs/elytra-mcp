"""CLI discovery and reversible explicit-run host configuration."""
import json
from pathlib import Path

from mirage_mcp.cli.main import main
from mirage_mcp.server import ControlPlaneServer
from mirage_mcp.sdk import RuntimeClient


def test_cli_scan_and_scoped_wrap_unwrap(tmp_path: Path, monkeypatch):
    cfg = tmp_path / 'host.json'
    original = {'mcpServers': {'github': {'command': 'npx', 'args': ['server'], 'env': {'KEEP': 'value'}, 'disabled': False}}, 'other': {'keep': True}}
    cfg.write_text(json.dumps(original))
    snapshot, graph = tmp_path / 'snapshot.json', tmp_path / 'graph.json'
    assert main(['scan', '--config', str(cfg), '--output', str(snapshot), '--json-output', str(graph)]) == 0
    assert snapshot.is_file() and graph.is_file()
    monkeypatch.delenv('ELYTRA_RUN_TOKEN', raising=False)
    assert main(['wrap', '--config', str(cfg)]) == 2
    assert json.loads(cfg.read_text()) == original
    server = ControlPlaneServer(port=0, db_path=tmp_path / 'live.db', auth_token='test-owner')
    try:
        base = server.start_background()
        run = RuntimeClient(base, token='test-owner').create_run('One explicit task')
        monkeypatch.setenv('ELYTRA_RUN_TOKEN', run['run_token'])
        args = ['wrap', '--config', str(cfg), '--run-id', run['run_id'], '--gateway', base]
        assert main(args) == 0
        wrapped = json.loads(cfg.read_text())
        entry = wrapped['mcpServers']['github']
        assert entry['command'] == 'elytra'
        assert run['run_id'] in entry['args']
        assert entry['env']['KEEP'] == 'value'
        assert entry['env']['ELYTRA_RUN_TOKEN'] == run['run_token']
        backup = cfg.with_suffix('.json.elytra.bak')
        assert json.loads(backup.read_text()) == original
        assert backup.stat().st_mode & 0o777 == 0o600
        assert main(args) == 1  # Existing backup is never overwritten.
        wrapped['other']['new_setting'] = 'preserved'
        cfg.write_text(json.dumps(wrapped))
        assert main(['unwrap', '--config', str(cfg)]) == 0
        restored = json.loads(cfg.read_text())
        assert restored['mcpServers'] == original['mcpServers']
        assert restored['other']['new_setting'] == 'preserved'
    finally:
        server.shutdown()
