.PHONY: training-up training-down training-status beginner-defense attack-defense-demo attack-defense-reset attack-defense-test attack-defense-runtime-work attack-defense-ha-demo attack-defense-ha-status

# 감사 2.1: 모든 docker compose 기동 경로가 하드닝 오버레이(리소스/rootfs 하드닝)를 함께 로드.
COMPOSE := docker compose -f docker-compose.yml -f infra/hardening/docker-compose.hardening.yml

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

# 팀 취약 서비스는 internal 망에 격리되어 host 에서 직접 도달할 수 없다. ad_target_gateway 가
# attack-surface 가 광고하는 게임 포트(9101~9303)를 host 에 발행해 참가자(Red 포털 브라우저)가
# 실제로 공격할 수 있게 한다 -- 반드시 함께 기동한다.
attack-defense-demo:
	$(COMPOSE) up -d --build auth attack_defense ad_registry ad_target_gateway ad_team_01_notes ad_team_01_vault ad_team_02_notes ad_team_02_vault ad_team_03_notes ad_team_03_vault ad_team_01_grid ad_team_02_grid ad_team_03_grid
	python3 -m scripts.bootstrap_attack_defense_demo

# 공방 리셋: 매치/라운드/플래그 상태와 팀 서비스 데이터를 비우고 새 매치를 부트스트랩한다.
# (영구 볼륨의 옛 매치가 오래 방치되면 라운드가 다운타임 보정으로 고착되고 플래그 valid_until 이
#  만료돼 flag 제출이 invalid_or_inactive 로 거부된다 -- 그 상태를 깨끗이 초기화한다.)
attack-defense-reset:
	-$(COMPOSE) rm -sf attack_defense ad_postgres ad_team_01_notes ad_team_01_vault ad_team_01_grid ad_team_02_notes ad_team_02_vault ad_team_02_grid ad_team_03_notes ad_team_03_vault ad_team_03_grid
	-docker volume rm cyber-range-platform_ad_postgres_data cyber-range-platform_ad_data cyber-range-platform_ad_team_01_notes_data cyber-range-platform_ad_team_01_vault_data cyber-range-platform_ad_team_01_grid_data cyber-range-platform_ad_team_02_notes_data cyber-range-platform_ad_team_02_vault_data cyber-range-platform_ad_team_02_grid_data cyber-range-platform_ad_team_03_notes_data cyber-range-platform_ad_team_03_vault_data cyber-range-platform_ad_team_03_grid_data
	$(MAKE) attack-defense-demo

attack-defense-test:
	pytest -q tests/attack_defense services/attack_defense/demo_services/*/test_service.py

attack-defense-runtime-work:
	python3 -m services.attack_defense.cli ad runtime-work

attack-defense-ha-demo:
	$(COMPOSE) stop attack_defense
	$(COMPOSE) --profile ad-ha up -d --build --wait --wait-timeout 180 --scale attack_defense_ha=2 auth ad_registry ad_postgres ad_team_01_notes ad_team_01_vault ad_team_02_notes ad_team_02_vault ad_team_03_notes ad_team_03_vault attack_defense_ha ad_ha_gateway
	ATTACK_DEFENSE_API_URL=http://localhost:8110 python3 -m scripts.bootstrap_attack_defense_demo

attack-defense-ha-status:
	ATTACK_DEFENSE_API_URL=http://localhost:8110 python3 -m services.attack_defense.cli ad ha-status
