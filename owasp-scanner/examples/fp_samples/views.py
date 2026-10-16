# AI 오탐 검토 테스트용 예제 코드입니다. 운영 환경에 사용하지 마세요.
import hashlib
import sqlite3
import subprocess

from flask import request


def cache_key(data: bytes) -> str:
    return "cache/" + hashlib.md5(data).hexdigest() + ".bin"


def disk_usage() -> bytes:
    return subprocess.run("df -h /", shell=True, capture_output=True).stdout


def run_tool() -> bytes:
    tool = request.args.get("tool", "")
    return subprocess.run("convert " + tool, shell=True, capture_output=True).stdout


def get_user(conn: sqlite3.Connection):
    user_id = int(request.args.get("id", "0"))
    return conn.execute("SELECT name FROM users WHERE id = %d" % user_id).fetchone()


def search_users(conn: sqlite3.Connection):
    keyword = request.args.get("q", "")
    return conn.execute(f"SELECT name FROM users WHERE name LIKE '%{keyword}%'").fetchall()
