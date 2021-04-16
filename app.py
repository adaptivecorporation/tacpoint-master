from flask import Flask, jsonify, request
from flask_caching import Cache
from flask_restful import Resource, Api
from flask_cors import CORS, cross_origin
from flask_compress import Compress
import uuid
import conf
import constants
import pymysql.cursors
import pymongo
import datetime
from bson.objectid import ObjectId
from redis import Redis
from rq import Worker, Queue, Connection
import os
from werkzeug.security import generate_password_hash, check_password_hash
from tokenUtil import generateToken, token_required, generatePwdToken, checkPwdResetToken


mongoclient = pymongo.MongoClient(constants.mongoclient)

tacpoint_db = mongoclient["tacpoint"]
tacpoint_col = tacpoint_db[conf.cluster_id]

app = Flask(__name__)
api = Api(app)
Compress(app)
cors = CORS(app)
cache = Cache(app)
app.config['CORS_HEADERS'] = 'Content-Type'

BASE_URL = '/api/v0/'

server = os.environ.get('REDIS_HOST')
redis_conn = Redis(server)
q = Queue(connection=redis_conn)

def open_connection():
    try:
        con = pymysql.connect(host=constants.DB_HOST, user=constants.DB_USER, password=constants.DB_PASSWORD, database=constants.DB_NAME, cursorclass=pymysql.cursors.DictCursor)

    except Exception as error:
        print(error)
    return con

#### AUTH ####

@app.route(BASE_URL + '/auth/login', methods=['POST'])
def login():
    status = 500
    message = 'Internal Server Error'
    con = open_connection()

    try:
        data = request.get_json()
        if 'password' in data and 'username' in data:
            queryGetUser = 'select * from users where username = "{0}";'.format(data['username'])
            cur = con.cursor()
            cur.execute(queryGetUser)
            result = cur.fetchall()
            cur.close()
            if len(result) > 0:
                if check_password_hash(result[0]['password'] , data['password']):
                    token = generateToken(data['username'])
                    print(token) 
                    return jsonify({'token': token, 'userId': result[0]['user_id'], 'userName': result[0]['username']}), 200
                else:
                    status = 403
                    message = 'Invalid password'
            else:
                print('error email')
                status = 403
                message = 'Invalid email'
        else:
            status = 400
            message = 'Password and Email are required'

        return jsonify({'message': message}), status

    except Exception as error:
        con.rollback()
        message = error
        print(error)

@app.route(BASE_URL + '/auth/reset-password', methods=['PUT'])
@token_required
def resetPassword(current_user):
    status = 500
    message = 'Internal Server Error'
    con = open_connection()
    try:
        data = request.get_json()
        if 'current_password' in data and 'new_password' in data:
            queryGetUser = 'select * from user where username = "{0}";'.format(current_user['username'])
            cur = con.cursor()
            cur.execute(queryGetUser)
            result = cur.fetchall()
            cur.close()
            if len(result) > 0:
                result[0]['username'] 
                if check_password_hash(result[0]['password'] , data['current_password']):
                    hashed_password = generate_password_hash(data['new_password'], method='sha256')
                    updateQuery = 'update users set password="{0}" where username="{1}";'.format(hashed_password, current_user['email'])
                    cur1 = con.cursor()
                    cur1.execute(updateQuery)
                    con.commit()
                    cur1.close()
                    return jsonify({'message': 'Password changed'}), 200
                else:
                    status = 400
                    message = 'Incorrect Current Password'
            else:
                status = 400
                message = 'User not found'
        else:
            status = 400
            message = 'Current Password, New Password and Email are required'

        return jsonify({'message': message}), status
    except Exception as error:
        con.rollback()
        message = error
        print(error)
    return jsonify({'message': message}), status

@app.route(BASE_URL + '/auth/generate-link/<email>', methods=['GET'])
def generatePwdLink(email):
    status = 500
    message = 'Internal Server Error'
    con = open_connection()
    try:
        queryGetUser = 'select * from user where username = "{0}";'.format(email)
        cur = con.cursor()
        cur.execute(queryGetUser)
        result = cur.fetchall()
        cur.close()
        if len(result) > 0:
            pwdToken = generatePwdToken(result[0]['username'], result[0]['id'])
            return jsonify({'pwdToken': pwdToken}), 200
        else:
            status = 400
            message = 'User is not registered'
    except Exception as error:
        message = error
        print(error)
    return jsonify({'message': message}), status

@app.route(BASE_URL + '/auth/check-pwd-token/<token>', methods=['GET'])
def checkPwdToken(token):
    print('Token Check Request Recieved >>> ')
    status = 500
    message = 'Internal Server Error'
    try:
        result = checkPwdResetToken(token)
        print(result)
        if len(result) > 0:
            return jsonify({'userId': result[0]['id']}), 200
        else:
            status = 400
            message = 'Invalid token'
    except Exception as error:
        message = error
        print(error)
    return jsonify({'message': message}), status

@app.route(BASE_URL + '/auth/change-pwd', methods=['PUT'])
@token_required
def passwordReset():
    status = 500
    message = 'Internal Server Error'
    con = open_connection()
    try:
        data = request.get_json()
        if 'password' in data and 'user' in data:
            queryGetUser = 'select * from users where username = "{0}";'.format(data['username'])
            cur = con.cursor()
            cur.execute(queryGetUser)
            result = cur.fetchall()
            cur.close()
            if len(result) > 0:
                hashed_password = generate_password_hash(data['password'], method='sha256')
                updateQuery = 'update user set password="{0}" where username="{1}";'.format(hashed_password, result[0]['email'])
                cur1 = con.cursor()
                cur1.execute(updateQuery)
                con.commit()
                cur1.close()
                return jsonify({'message': 'Password changed'}), 200
            else:
                status = 400
                message = 'User not found'
        else:
            status = 400
            message = 'Invalid Input'

        return jsonify({'message': message}), status
    except Exception as error:
        con.rollback()
        message = error
        print(error)
    return jsonify({'message': message}), status

@app.route(BASE_URL + '/auth/register', methods=['POST'])
def createUser():
    status = 500
    message = 'Internal Server Error'
    con = open_connection()
    user_id = uuid.uuid4()
    try:
        
        data = request.get_json()
        if 'name' in data and 'password' in data and 'email' in data and 'username' in data:
            hashed_password = generate_password_hash(data['password'], method='sha256')
            query = 'insert into users (username, password, name, email, id) VALUES ("{0}","{1}","{2}","{3}","{4}");'.format(data['username'], hashed_password, data['name'], data['email'], user_id)
            print(query)
            with con:
                cur = con.cursor()
                cur.execute(query)
                con.commit()
                cur.close()
                return jsonify({'message': 'User created'}), 200
        else:
            status = 400
            message = 'Name, Email and Password are required'

        return jsonify({'message': message}), status
    except Exception as error:
        print(error)
        con.rollback()
        message = error
    
    return jsonify({'message': message}), status


#### END AUTH ####



@app.route(BASE_URL + 'sysinfo/<ep_id>', methods=['GET'])
@token_required
def get_EP_SysInfo(current_user, ep_id):
    con = open_connection()
    query = 'select * from endpoints where cluster_id="{0}" and endpoint_id="{1}"'.format(conf.cluster_id, ep_id)
    try:
        cur = con.cursor()
        cur.execute(query)
        res = cur.fetchall()
        cur.close()
    except Exception as error:
        print(error)
        return jsonify({"message": "error"})
    clusterid = conf.cluster_id
    resp = tacpoint_col.find_one({"_id": ObjectId(res[0]['document_id'])}, {'_id': False})
    print(resp)
    return jsonify({'sysinfo': resp})

@cache.cached(timeout=60)
@app.route(BASE_URL + "dashinfo", methods=['GET'])
def dashInfo():
    con = open_connection()
    ep_query = 'select * from endpoints order by last_connection limit 1'
    tasks_query = 'select * from task_list where is_completed=0'
    try:
        cur = con.cursor()
        cur.execute(ep_query)
        latest_ep = cur.fetchall()
        cur.execute(tasks_query)
        task_list = cur.fetchall()
        cur.close()

    except Exception as error:
        print(error)
        return jsonify({'message': 'system error'})
    return jsonify({'latest_ep': latest_ep[0], 'tasks': task_list})

@app.route(BASE_URL + "ep/latest-check-in", methods=['GET'])
def latestCheckIn():
    con = open_connection()
    query = 'select * from endpoints order by last_connection limit 1'
    try:
        cur = con.cursor()
        cur.execute(query)
        res = cur.fetchall()
        cur.close()

    except Exception as error:
        print(error)
        return jsonify({'message': 'system error'})
    return jsonify({'latest_ep': res[0]})

@app.route(BASE_URL + 'tasks/list', methods=['GET'])
@token_required
def listTasks(current_user):
    con = open_connection()
    query = 'select * from tasks'
    try:
        cur = con.cursor()
        cur.execute(query)
        res = cur.fetchall()
        cur.close()
    except Exception as error:
        print(error)
        return jsonify({"message": "error"})
    return jsonify({'tasks': res})

@app.route(BASE_URL + 'tasks/create', methods=['PUT'])
@token_required
def createTask(current_user):
    data = request.get_json()
    con = open_connection()
    task = data['task']
    target = data['target']
    if 'data' in data: data = data['data']
    else: data = ''
    query = "insert into task_list (task_id, cluster_id, endpoint_id, task, data) values ('{0}','{1}','{2}','{3}','{4}')".format(uuid.uuid4(),conf.cluster_id, target, task, data)
    try:
        cur = con.cursor()
        cur.execute(query)
        con.commit()
        cur.close()

    except Exception as error:
        print(error)
        return jsonify({'message':'server error'}),500
    return jsonify({'message': 'task created', 'target': target}),200

@app.route(BASE_URL + 'getEndpoints', methods=['GET'])
@token_required
def getEndpoints(current_user):
    con = open_connection()
    query = 'select * from endpoints where cluster_id="{0}"'.format(conf.cluster_id)
    try:
        cur = con.cursor()
        cur.execute(query)
        res = cur.fetchall()
        cur.close()

    except Exception as error:
        print(error)
        return jsonify({'message': 'server error'}),500
    return jsonify({'endpoints': res})

@app.route(BASE_URL + 'db/ep_id/<ep_id>', methods=['GET'])
def db_GetEndpointInfo(ep_id):
    con = open_connection()
    query = 'select * from endpoints where endpoint_id="{0}"'.format(ep_id)

    try:
        cur = con.cursor()
        cur.execute(query)
        res = cur.fetchall()

    except Exception as error:
        print(error)
        return jsonify({'message': 'server error'}),500
    return jsonify({'ep': res[0]})

@app.route(BASE_URL + 'db/cluster_id/<cluster_id>', methods=['GET'])
def db_getClusterInfo(cluster_id):
    con = open_connection()
    query = 'select * from clusters where cluster_id="{0}"'.format(cluster_id)

    try:
        cur = con.cursor()
        cur.execute(query)
        res = cur.fetchall()

    except Exception as error:
        print(error)
        return jsonify({'message': 'server error'}),500
    return jsonify({'cluster': res[0]})


if __name__ == '__main__':
	app.run(debug=True, host='0.0.0.0', port=5000)