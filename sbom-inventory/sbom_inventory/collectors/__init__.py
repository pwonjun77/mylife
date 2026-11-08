"""수집기(collector) 모음.

모든 수집기는 동일한 형태의 결과를 돌려준다: list[HostRecord]
  - HostRecord.asset      : 장비 식별 정보 (hostname / serial / MAC / IP / OS)
  - HostRecord.components : 그 장비에서 관측된 소프트웨어/서비스 목록
저장소(store.py)가 식별자를 기준으로 서로 다른 출처의 레코드를 한 자산으로 병합한다.
"""
