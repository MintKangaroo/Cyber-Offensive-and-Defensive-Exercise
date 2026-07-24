# FOR-000 방어 해법

평문 자격증명을 볼트(HashiCorp Vault, Windows DPAPI 등)로 이관하고, 백업 설정 파일에는
시크릿 참조(예: `${vault:backup/password}`)만 남긴다. 접근 제어(최소권한)도 함께 적용.
