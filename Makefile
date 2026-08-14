.PHONY: training-up training-down training-status beginner-defense attack-defense-demo attack-defense-test attack-defense-runtime-work attack-defense-ha-demo attack-defense-ha-status

training-up:
	python3 -m scripts.training_environment up

training-down:
	python3 -m scripts.training_environment down

training-status:
	python3 -m scripts.training_environment status

# Beginner Blue Team defense: build the patched image, submit it, drive the
# runtime worker and validate the fix -- all in one command, no Docker knowledge
# required. Advanced users can still use the manual patch workflow.
beginner-defense:
	python3 -m scripts.beginner_defense

attack-defense-demo:
	docker compose up -d --build auth attack_defense ad_registry ad_team_01_notes ad_team_01_vault ad_team_02_notes ad_team_02_vault ad_team_03_notes ad_team_03_vault
	python3 -m scripts.bootstrap_attack_defense_demo

attack-defense-test:
	pytest -q tests/attack_defense services/attack_defense/demo_services/*/test_service.py

attack-defense-runtime-work:
	python3 -m services.attack_defense.cli ad runtime-work

attack-defense-ha-demo:
	docker compose stop attack_defense
	docker compose --profile ad-ha up -d --build --wait --wait-timeout 180 --scale attack_defense_ha=2 auth ad_registry ad_postgres ad_team_01_notes ad_team_01_vault ad_team_02_notes ad_team_02_vault ad_team_03_notes ad_team_03_vault attack_defense_ha ad_ha_gateway
	ATTACK_DEFENSE_API_URL=http://localhost:8110 python3 -m scripts.bootstrap_attack_defense_demo

attack-defense-ha-status:
	ATTACK_DEFENSE_API_URL=http://localhost:8110 python3 -m services.attack_defense.cli ad ha-status
