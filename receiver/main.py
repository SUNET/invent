#!/usr/bin/env python3
import datetime
import logging
import os
import os.path
import sqlite3
import time
import uuid
from os import makedirs
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, Request, Response, UploadFile, status
from fastapi.logger import logger
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates

# Security singleton
security = HTTPBasic()
uvicorn_logger = logging.getLogger('uvicorn.error')
logger.handlers = uvicorn_logger.handlers

class Inventory:

    def __init__(self) -> None:

        try:
            self.admin_password = os.environ["INVENT_ADMIN_PASSWORD"]
        except KeyError:
            self.admin_password = uuid.uuid4().hex 
            logger.error(f'INFO:\tINVENT_ADMIN_PASSWORD not set, admin password set to: `{self.admin_password}` for this session.')
        try:
            self.disable_tofu = os.environ["INVENT_DISABLE_TOFU"].lower() in [ 'true', 'yes', '1', 'y']
        except KeyError:
            self.disable_tofu = False
        try:
            self.host_dir = os.environ["INVENT_HOST_DIR"]
        except KeyError:
            self.host_dir = '/var/cache/invent/hosts'
        try:
            self.image_dir = os.environ["INVENT_IMAGE_DIR"]
        except KeyError:
            self.image_dir = '/var/cache/invent/images'
        try:
            self.db_dir = os.environ["INVENT_DB_DIR"]
        except KeyError:
            self.db_dir = '/etc/invent/db'
        if not os.path.isdir(self.host_dir):
            makedirs(self.host_dir)
        if not os.path.isdir(self.image_dir):
            makedirs(self.image_dir)
        if not os.path.isdir(self.db_dir):
            makedirs(self.db_dir)

        self.admin_salt = uuid.uuid4().hex
        self.ph = PasswordHasher()
        self.db = sqlite3.connect(os.path.join(self.db_dir, "users.db"))
        self.cursor = self.db.cursor()
        self.cursor.execute("CREATE TABLE IF NOT EXISTS users(username, salt, hash, endpoint)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS reports(username, timestamp, endpoint)")



    def get_or_create_user(self, credentials: Annotated[HTTPBasicCredentials, Depends(security)], endpoint: str) -> tuple[str,str]:
        username = credentials.username
        query = self.cursor.execute(f"SELECT salt, hash FROM users WHERE username='{username}' and endpoint='{endpoint}'")
        result = query.fetchone()
        # If the user is not in the database, we will trust the user and add it to the database
        # TOFU: https://developer.mozilla.org/en-US/docs/Glossary/TOFU
        if result is None and not self.disable_tofu:
            salt = uuid.uuid4().hex
            hash = self.ph.hash(salt + credentials.password) 
            self.cursor.execute(f"INSERT INTO users (username, salt, hash, endpoint) values('{username}', '{salt}', '{hash}', '{endpoint}')")
            self.db.commit()
            return (salt, hash)
        # FIXME: How can we best communicate that the user was not in the db?
        if result is None and self.disable_tofu:
            salt = uuid.uuid4().hex
            hash = self.ph.hash(salt + uuid.uuid4().hex) 
            return (salt, hash)
        else:
            return result

    def validate_credentials(self, credentials: Annotated[HTTPBasicCredentials, Depends(security)], salt: str, hash: str) -> bool:
        password = credentials.password
        try:
            self.ph.verify(hash, salt + password)
        except VerifyMismatchError:
            return False
        return True

    async def upload(self, endpoint: str, file: UploadFile, name: str, credentials: Annotated[HTTPBasicCredentials, Depends(security)], response: Response):
        dir = self.host_dir
        if endpoint == 'image':
            dir = self.image_dir

        if credentials.username != name:
            response.status_code = status.HTTP_403_FORBIDDEN
            return {"ERROR": "Username and endpoint does not match"}
        salt, hash = self.get_or_create_user(credentials, endpoint)
        if self.validate_credentials(credentials, salt, hash):
            filename = os.path.join(dir, name + '.json')
            with open(filename, 'w') as fh:
                contents: bytes = await file.read()
                fh.write(contents.decode('utf-8'))

            return {"SUCCESS": f"File: {filename} saved"}
        else:
            try:
                query = self.cursor.execute(f"SELECT * FROM reports WHERE username='{credentials.username}' and endpoint={endpoint}")
                result = query.fetchone()
            except sqlite3.OperationalError:
                result = None
            if result is None:
                timestamp = int(time.time())
                self.cursor.execute(f"INSERT INTO reports (username, timestamp, endpoint) values('{credentials.username}','{timestamp}','{endpoint}')")
                self.db.commit()
                response.status_code = status.HTTP_401_UNAUTHORIZED
            return {"ERROR": "Invalid password, this incident will be reported"}


app = FastAPI()
inventory = Inventory()
templates = Jinja2Templates(directory="templates")

@app.post("/host/{hostname}", status_code=status.HTTP_201_CREATED)
async def upload_host(file: UploadFile, hostname: str, credentials: Annotated[HTTPBasicCredentials, Depends(security)], response: Response):
    return await inventory.upload('host', file, hostname, credentials, response)

@app.post("/image/{imagename}", status_code=status.HTTP_201_CREATED)
async def upload_image(file: UploadFile, imagename: str, credentials: Annotated[HTTPBasicCredentials, Depends(security)], response: Response):
    return await inventory.upload('image', file, imagename, credentials, response)

@app.get("/admin", response_class=HTMLResponse)
async def show_admin_interface(credentials: Annotated[HTTPBasicCredentials, Depends(security)], request: Request):
    hash = inventory.ph.hash(inventory.admin_salt + inventory.admin_password) 
    if not inventory.validate_credentials(credentials, inventory.admin_salt, hash) and credentials.username != 'admin':
        return templates.TemplateResponse('unauthorized.html', {"request": request})

    query = inventory.cursor.execute(f"SELECT * FROM reports")
    result = query.fetchall()
    reports = list()
    for res in result:
        reports.append({"username": res[0],"timestamp":  datetime.datetime.fromtimestamp(int(res[1])), "endpoint": res[2]})
    return templates.TemplateResponse("admin.html", {"request": request, "reports": reports})
@app.post("/admin/{endpoint}/{name}", response_class=HTMLResponse)
async def delete_report_and_reset_user(endpoint: str, name: str, credentials: Annotated[HTTPBasicCredentials, Depends(security)], request: Request):
    hash = inventory.ph.hash(inventory.admin_salt + inventory.admin_password) 
    if not inventory.validate_credentials(credentials, inventory.admin_salt, hash) and credentials.username != 'admin':
        return templates.TemplateResponse('unauthorized.html', {"request": request})
    inventory.cursor.execute(f"DELETE FROM reports where username='{name}' and endpoint='{endpoint}'")
    inventory.db.commit()
    inventory.cursor.execute(f"DELETE FROM users where username='{name}' and endpoint='{endpoint}'")
    inventory.db.commit()
    return templates.TemplateResponse('delete_report_and_reset_user.html', {"request": request, "username": name, "endpoint": endpoint})
