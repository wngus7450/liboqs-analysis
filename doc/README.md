# doc/ LaTeX 문서 빌드 가이드

이 디렉터리는 `liboqs-analysis` 라이브러리 기술 문서를 LaTeX로 관리합니다.

## 파일 구성
- `main.tex`: 문서 메인 엔트리
- `sections/*.tex`: 장별 분리 문서
- `figures/`: 이미지/다이어그램 리소스

## 빌드 방법
프로젝트 루트(`/home/wngus/projects/liboqs-analysis`) 또는 `doc/`에서 실행:

```bash
cd /home/wngus/projects/liboqs-analysis/doc
pdflatex -interaction=nonstopmode main.tex
pdflatex -interaction=nonstopmode main.tex
```

`latexmk`가 설치되어 있으면 아래 명령 권장:

```bash
cd /home/wngus/projects/liboqs-analysis/doc
latexmk -pdf -interaction=nonstopmode main.tex
```

## 출력물
- `main.pdf`: 최종 설명서

## 비고
- 한국어 본문 렌더링을 위해 TeX 배포판에 `kotex` 패키지가 필요합니다.
- 빌드 오류 시 누락 패키지 설치 후 재시도하세요.
