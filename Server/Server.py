#!/usr/bin/env python

import sys
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes

sys.path.append("..")

from utilities import *

# from Crypto import Signature
# from Crypto.Cipher import AES
# from Crypto.Cipher import PKCS1_OAEP


def main():
    database = "server.db"

    sql_create_usernames_table = """ CREATE TABLE IF NOT EXISTS usernames(
                                        id integer primary key AUTOINCREMENT,
                                        name nvarchar(40) not null,
                                        password nvarchar(32) not null,
                                        publickey varchar(1000) not null
                                    ); """

    # create a database connection
    conn = create_connection(database)
    if conn is not None:
        # create projects table
        create_table(conn, sql_create_usernames_table)
    else:
        print("Error! cannot create the database connection.")
    # Tcp_connect("127.0.0.1", 17098)
    while True:
        print("Waiting for a client")
        Tcp_server_wait(5, 17098, "127.0.0.1")
        Tcp_server_next()
        option = Tcp_Read().decode()
        option = option.strip("\n")
        if option == "0":
            print("Creating new user")
            Tcp_Write("Registering...")
            username = Tcp_Read().decode()
            username = username.strip("\n")
            password = Tcp_Read().decode()
            password = password.strip("\n")
            publickey = base64.b64decode(Tcp_Read()).decode()
            publickey = publickey.strip("\n")
            print(username, password)
            cursor = conn.cursor()
            cursor.execute(
                "insert into usernames (name, password, publickey) values (?, ?, ?)",
                (
                    username,
                    password,
                    publickey,
                ),
            )
            conn.commit()
            print("Inserted")

        elif option == "1":
            print("Login process")
            Tcp_Write("Logging in...")
            username = Tcp_Read().decode()
            username = username.strip("\n")
            password = Tcp_Read().decode()
            password = password.strip("\n")
            cursor = conn.cursor()
            cursor.execute("select * from usernames where name = ?", (username,))
            rows = cursor.fetchall()
            if not rows:
                print("Invalid!")
                Tcp_Write("0")
            else:
                Tcp_Write("1")
                random_token = get_random_bytes(16)

                # for digital signature

                key = RSA.importKey(rows[0][3].encode())
                key = pkcs1_15.new(key)
                hash = SHA256.new(random_token)
                Tcp_Write(base64.b64encode(random_token))
                signature = base64.b64decode(Tcp_Read()).strip(b"\n")

                try:
                    key.verify(hash, signature)
                    print("Authentication successful!")
                    # print(password)
                    Tcp_Write("Successful")
                except (ValueError, TypeError):
                    print("Password mismatch!")
                    Tcp_Write("Wrong Password")

                # for symmetric and asymmetric

                # password_in_db = rows[0][2]
                # key = PKCS1_OAEP.new(key)
                # Tcp_Write(base64.b64encode(key.encrypt(random_token)))
                # obj = AES.new(random_token, AES.MODE_CBC, 16 * b"\x00")
                # ciphertext = obj.encrypt(password_in_db.encode())
                # read_encrypted_hash = Tcp_Read()
                # read_encrypted_hash = read_encrypted_hash.strip(b"\n")

                # if read_encrypted_hash == ciphertext:
                #     print("Authentication successful!")
                #     # print(password)
                #     Tcp_Write("Successful")
                # else:
                #     print("Password mismatch!")
                #     Tcp_Write("Wrong Password")
        else:
            pass
            # print("Pass")

        # Tcp_Close()
        print("--- New connection ---")


if __name__ == "__main__":
    main()
