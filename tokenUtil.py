from flask import Flask, jsonify, request
from functools import wraps
import jwt
import datetime
import constants
import pymysql.cursors
from cryptography.fernet import Fernet
import os

key = Fernet.generate_key()
cipher_suite = Fernet(key)

# def open_connection():
# 	unix_socket = '/cloudsql/{}'.format(constants.db_connection_name)
# 	try:
		
# 		conn = pymysql.connect(user=constants.db_user, password=constants.db_password,
# 							unix_socket=unix_socket, db=constants.db_name,
# 							cursorclass=pymysql.cursors.DictCursor
# 							)
# 	except pymysql.MySQLError as e:
# 		print(e)

# 	return conn

def open_connection():
    try:
        con = pymysql.connect(host=constants.DB_HOST, user=constants.DB_USER, password=constants.DB_PASSWORD, database=constants.DB_NAME, cursorclass=pymysql.cursors.DictCursor)

    except Exception as error:
        print(error)
    return con

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, constants.SECRET_KEY)
            con = open_connection()
            try:
                queryGetUser = 'select * from user where email = "{0}";'.format(data['email'])
                cur = con.cursor()
                cur.execute(queryGetUser)
                result = cur.fetchall()
            except Exception as error:
                print(error)
        except Exception as error:
            print(error)

            return jsonify({'message' : 'Token is invalid!'}), 401
        
        return f(result[0], *args, **kwargs)

    return decorated



def generateToken(username):
    try:
        token = jwt.encode({'username' : username, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=constants.expireTime)}, constants.SECRET_KEY)
        return token.decode('UTF-8')
    except Exception as error:
        print(error)


def generatePwdToken(username, email, id):
    try:
        token = jwt.encode({'username' : username, 'email': email, 'id': id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=constants.pwdExpireTime)}, constants.PWD_SECRET_KEY)
        return token.decode('UTF-8')
    except Exception as error:
        print(error)

def checkPwdResetToken(token):
    print(token)
    try:
        data = jwt.decode(token, constants.PWD_SECRET_KEY)
        print(data)
        con = open_connection()
        with con:
            queryGetUser = 'select * from user where email = "%s";' % (data['email'])
            cur = con.cursor()
            cur.execute(queryGetUser)
            result = cur.fetchall()
            cur.close()
            return result
    except Exception as error:
        print(error)
        return []
