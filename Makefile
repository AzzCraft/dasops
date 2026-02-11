.PHONY: help
help:
	@echo "Targets:"
	@echo "  install       - install CLI deps"
	@echo "  install-gui   - install GUI deps"
	@echo "  gui           - run the Streamlit GUI"

.PHONY: install
install:
	python -m pip install -r requirements.txt

.PHONY: install-gui
install-gui:
	python -m pip install -r requirements-gui.txt

.PHONY: gui
gui:
	streamlit run gui/app.py
