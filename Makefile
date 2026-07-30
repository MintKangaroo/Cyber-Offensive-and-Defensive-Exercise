.PHONY: attack-defense-demo attack-defense-test attack-defense-runtime-work

attack-defense-demo:
	docker compose up -d --build auth attack_defense ad_registry ad_team_01_notes ad_team_01_vault ad_team_02_notes ad_team_02_vault ad_team_03_notes ad_team_03_vault
	python3 -m scripts.bootstrap_attack_defense_demo

attack-defense-test:
	pytest -q tests/attack_defense services/attack_defense/demo_services/*/test_service.py

attack-defense-runtime-work:
	python3 -m services.attack_defense.cli ad runtime-work
