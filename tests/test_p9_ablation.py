from pathlib import Path


def test_p9_script_exists_and_labels_external_scope_honestly():
    path = Path("benchmarks/p9_contribution_ablation.py")
    text = path.read_text(encoding="utf-8")
    assert "not external products" in text.lower()
    assert "B5 / V4+fanout" in text
    assert "not measured" in text.lower()
