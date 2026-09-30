.PHONY: training-up training-down training-status beginner-defense attack-defense-demo attack-defense-reset attack-defense-test attack-defense-runtime-work attack-defense-ha-demo attack-defense-ha-status rehearsal rehearsal-down

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

# 무인 리허설(Phase 3): Live Fire(이벤트 파이프라인) + Attack/Defense 2라운드를 봇으로 완주하고
# 점수-원장 일치(유실 0)·SIEM 팀 귀속·AAR PDF(한글) 를 검증한다. 메모리 제약상 전체 스택 대신
# 리허설에 필요한 서브셋만 기동한다(이벤트 파이프라인 + A/D notes 서브셋).
# ★깨끗한 플래그로 시작하려면 먼저 `make attack-defense-reset`(고착 매치/스테일 볼륨 정리).
REHEARSAL_SVCS := config_service event_collector scoring_engine ingest_proxy siem_api aar_report \
	power_plant pp_gateway auth attack_defense ad_registry ad_target_gateway \
	ad_team_01_notes ad_team_02_notes ad_team_03_notes

# 리허설 오버라이드: 트윈이 depends_on 하는 edr_backend 의 host 포트 발행을 제거해, host 8080 이
# 점유된 환경에서도 기동이 실패하지 않게 한다(edr 컨테이너 내부 8080 은 유지 → 서비스간 통신 정상).
REHEARSAL_COMPOSE := $(COMPOSE) -f loadtest/rehearsal-override.yml

rehearsal:
	$(REHEARSAL_COMPOSE) up -d --build $(REHEARSAL_SVCS)
	@echo "서비스 준비 대기(15s)…"; sleep 15
	python3 -m scripts.rehearsal.run_rehearsal --stage all \
		--json loadtest/results/rehearsal_latest.json

# 리허설 서브셋만 내린다(볼륨 유지). 전체 정리는 `$(COMPOSE) down -v`.
rehearsal-down:
	$(REHEARSAL_COMPOSE) stop $(REHEARSAL_SVCS)
	$(REHEARSAL_COMPOSE) rm -f $(REHEARSAL_SVCS)
