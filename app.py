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

mongoclient = pymongo.MongoClient(constants.mongoclient)

tacpoint_db = mongoclient["tacpoint"]
tacpoint_col = tacpoint_db[conf.cluster_id]

app = Flask(__name__)
api = Api(app)
Compress(app)
cors = CORS(app)
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


@app.route(BASE_URL + 'sysinfo/<ep_id>', methods=['GET'])
def get_EP_SysInfo(ep_id):
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

@app.route(BASE_URL + 'api/tasks/list', methods=['GET'])
def listTasks():
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

@app.route(BASE_URL + 'api/tasks/create', methods=['PUT'])
def createTask():
    data = request.get_json()
    con = open_connection()
    task = data['task']
    target = data['target']
    data = data['data']
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

@app.route(BASE_URL + 'api/getEndpoints', methods=['GET'])
def getEndpoints():
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


if __name__ == '__main__':
	app.run(debug=True, host='0.0.0.0', port=5000)