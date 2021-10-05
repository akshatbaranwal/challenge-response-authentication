import getpass
import hashlib
import socket
import sqlite3


def PasswordCreate():
    user_in = getpass.getpass()
    password = hashlib.md5()
    password.update(user_in.encode("utf-8"))
    return password.hexdigest()


def Tcp_connect(HostIp, Port):
    global s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.connect((HostIp, Port))
    # SocketServer.TCPServer.allow_reuse_address = True
    return


def Tcp_server_wait(numofclientwait, port, HostIp):
    global s2
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s2.bind((HostIp, port))
    s2.listen(numofclientwait)


def Tcp_server_next():
    global s
    s = s2.accept()[0]


def Tcp_Write(D):
    if isinstance(D, str):
        s.send((D + "\n").encode())
    else:
        s.send(D + b"\n")
    return


def Tcp_Read():
    a = b" "
    b = b""
    # import pdb
    # pdb.set_trace()
    while a != b"\n":
        a = s.recv(1)  # .decode()
        b = b + a
    return b


def Tcp_Close():
    s.close()
    return


def create_connection(db_file):
    """create a database connection to the SQLite database
    specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except:
        print("Cannot Create Connection")

    return None


def create_table(conn, create_table_sql):
    """create a table from the create_table_sql statement
    :param conn: Connection object
    :param create_table_sql: a CREATE TABLE statement
    :return:
    """
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except:
        print("Cannot Create Table")
