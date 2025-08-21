# SRA Ghost Protocol - Wednesday Demo Makefile

.PHONY: install demo ui verify clean test

# Quick install (run this first!)
install:
	pip install -e .
	pip install streamlit pandas requests

# Faculty demo (the main show)
demo:
	python demo/faculty_demo.py

# Streamlit UI (HCI showcase)
ui:
	streamlit run demo/ui/app.py

# Verify audit integrity
verify:
	python demo/verify_audit.py logs/demo_audit.jsonl

# Run tests
test:
	pytest tests/ -q

demo-s1:
	python demo/test_s1.py

# Clean everything
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	rm -f logs/*.jsonl

# Quick smoke test
smoke:
	@python -c "from sra.core import SRACore; print('✓ Core works')"
	@python -c "from sra.capabilities import mint; print('✓ HCI works')"
	@python -c "from attacks.base import AttackProbe; print('✓ Attacks work')"
	@echo "✓ All imports working!"