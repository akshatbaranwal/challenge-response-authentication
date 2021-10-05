#!/usr/bin/env python

import sys
import base64
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

sys.path.append("..")

from utilities import *

# from Crypto.Cipher import PKCS1_OAEP
# from Crypto.Cipher import AES


def main():
    database = "client.db"

    sql_create_usernames_table = """ CREATE TABLE IF NOT EXISTS usernames(
                                        id integer primary key AUTOINCREMENT,
                                        name nvarchar(40) not null,
                                        privatekey varchar(1000) not null
                                    ); """

    # create a database connection
    conn = create_connection(database)
    if conn is not None:
        # create projects table
        create_table(conn, sql_create_usernames_table)
    else:
        print("Error! cannot create the database connection.")

    Tcp_connect("127.0.0.1", 17098)

    option = input("Enter 1 for login, 0 registration: ")
    print(option)
    Tcp_Write(option)

    if option == "0":
        print(Tcp_Read().decode())
        username = input("Enter your login username: ")
        password = PasswordCreate()
        print(password)
        key = RSA.generate(1024)
        Tcp_Write(username)
        Tcp_Write(password)
        Tcp_Write(base64.b64encode(key.public_key().export_key()))
        cursor = conn.cursor()
        cursor.execute(
            "insert into usernames (name, privatekey) values (?, ?)",
            (
                username,
                key.export_key().decode(),
            ),
        )
        conn.commit()

    elif option == "1":
        print(Tcp_Read().decode())

        username = input("Enter your login username: ")
        password = PasswordCreate()
        print(password)
        Tcp_Write(username)
        Tcp_Write(password)

        existence = Tcp_Read().decode()
        existence = existence.strip("\n")

        false = "0"
        if existence == false:
            print("Username does not exist")
        else:
            cursor = conn.cursor()
            cursor.execute("select * from usernames where name = ?", (username,))
            rows = cursor.fetchall()
            key = RSA.importKey(rows[0][2].encode())

            # for digital signature

            key = pkcs1_15.new(key)
            random_token = base64.b64decode(Tcp_Read()).strip(b"\n")
            hash = SHA256.new(random_token)
            signature = key.sign(hash)
            Tcp_Write(base64.b64encode(signature))

            # for symmetric and asymmetric

            # key = PKCS1_OAEP.new(key)
            # random_token = key.decrypt(base64.b64decode(Tcp_Read()).strip(b"\n"))
            # obj = AES.new(random_token, AES.MODE_CBC, 16 * b"\x00")
            # ciphertext = obj.encrypt(password.encode())
            # Tcp_Write(ciphertext)

            auth_stat = Tcp_Read().decode()
            auth_stat = auth_stat.strip("\n")
            if auth_stat == "Wrong Password":
                print("Error, Cannot Log in!")
            else:
                print("Logged In!")
    print("Closing Connection")
    # Tcp_Close()


if __name__ == "__main__":
    while True:
        print("--- New connection ---")
        main()
