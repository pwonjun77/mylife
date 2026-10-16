# 의도적으로 취약하게 작성한 예제 코드입니다. 절대 운영 환경에 사용하지 마세요.
import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

import jwt
import requests
import yaml
from flask import Flask, request, send_file

app = Flask(__name__)
DEBUG = True
SECRET_KEY = "s3cr3t-hardcoded-key"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLQ"


@app.route("/user")
def get_user():
    conn = sqlite3.connect("app.db")
    uid = request.args.get("id")
    return str(conn.execute(f"SELECT * FROM users WHERE id = {uid}").fetchall())


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/download")
def download():
    return send_file(request.args.get("file"))


@app.route("/fetch")
def fetch():
    return requests.get(request.args.get("url"), verify=False).text


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    cfg = yaml.load(request.data)
    return str(obj) + str(cfg)


def make_token():
    session_token = random.randint(100000, 999999)
    return session_token


def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()


def check_login(user, password):
    app.logger.info(f"login attempt user={user} password={password}")
    try:
        claims = jwt.decode(request.cookies["jwt"], options={"verify_signature": False})
    except Exception:
        pass
    return eval(request.args.get("expr"))


def is_admin(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["role"] == "admin"
    except Exception:
        return True


def read_config(path):
    try:
        return open(path).read()
    except:
        return ""


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
