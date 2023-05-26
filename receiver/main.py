import sys
#!/usr/bin/env python3
import os
import os.path
import sqlite3
import uuid
from os import makedirs
import time
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends, FastAPI, Response, UploadFile, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials

# Security singleton
security = HTTPBasic()

class Inventory:

    def __init__(self):

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

        self.ph = PasswordHasher()
        self.db = sqlite3.connect(os.path.join(self.db_dir, "users.db"))
        self.cursor = self.db.cursor()
        self.cursor.execute("CREATE TABLE IF NOT EXISTS users(username, salt, hash)")
        self.cursor.execute("CREATE TABLE IF NOT EXISTS reports(username, timestamp, endpoint)")



    def get_or_create_user(self, credentials: Annotated[HTTPBasicCredentials, Depends(security)]) -> tuple[str,str]:
        username = credentials.username
        query = self.cursor.execute(f"SELECT salt, hash FROM users WHERE username='{username}'")
        result = query.fetchone()
        # If the user is not in the database, we will trust the user and add it to the database
        # TOFU: https://developer.mozilla.org/en-US/docs/Glossary/TOFU
        if result is None:
            salt = uuid.uuid4().hex
            hash = self.ph.hash(salt + credentials.password) 
            self.cursor.execute(f"INSERT INTO users (username, salt, hash) values('{username}', '{salt}', '{hash}')")
            self.db.commit()
            return (salt, hash)
        else:
            return result

    def validate_credentials(self,credentials: Annotated[HTTPBasicCredentials, Depends(security)], salt: str, hash: str) -> bool:
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
            return {"ERROR": "Username and andpoint does not match"}
        salt, hash = self.get_or_create_user(credentials)
        if self.validate_credentials(credentials, salt, hash):
            filename = os.path.join(dir, name + '.json')
            with open(filename, 'w') as fh:
                contents: bytes = await file.read()
                fh.write(contents.decode('utf-8'))

            return {"SUCCESS": f"File: {filename} saved"}
        else:
            query = self.cursor.execute(f"SELECT * FROM reports WHERE username='{credentials.username}' and endpoint={endpoint}")
            result = query.fetchone()
            if result is None:
                timestamp = int(time.time())
                self.cursor.execute(f"INSERT INTO reports (username, timestamp) values('{credentials.username}','{endpoint}', '{timestamp}')")
                self.db.commit()
                response.status_code = status.HTTP_401_UNAUTHORIZED
            return {"ERROR": "Invalid password, this incident will be reported"}


app = FastAPI()
inventory = Inventory()

@app.post("/host/{hostname}", status_code=status.HTTP_201_CREATED)
async def upload_host(file: UploadFile, hostname: str, credentials: Annotated[HTTPBasicCredentials, Depends(security)], response: Response):
    return await inventory.upload('host', file, hostname, credentials, response)

@app.post("/image/{imagename}", status_code=status.HTTP_201_CREATED)
async def upload_image(file: UploadFile, imagename: str, credentials: Annotated[HTTPBasicCredentials, Depends(security)], response: Response):
    return await inventory.upload('image', file, imagename, credentials, response)
