from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime
import bcrypt
from flask import Flask, request, jsonify
import consul
import json
import redis
import logging

from dotenv import load_dotenv
import os

app = Flask(__name__)
logger = logging.getLogger(__name__)

load_dotenv()

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')  # Change this to a strong secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=24)  # Token expiration time
jwt = JWTManager(app)

print(os.getenv('JWT_SECRET'))

cert_path = os.getenv('CERT_PATH')
key_path = os.getenv('KEY_PATH')
port = int(os.getenv('FLASK_PORT', 5000))


# Initialize Consul client
consul_client = consul.Consul(host='localhost', port=8500)
redis_client = redis.Redis(host='localhost', port=6379, db=0)


# Function to hash a password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Function to check if a password matches the hashed password
def check_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)


users = {
    "user": hash_password("password123")
}

@jwt.unauthorized_loader
def unauthorized_response(callback):
    return jsonify({
        'error': 'Authorization required',
        'description': 'Request does not contain an access token'
    }), 401

@jwt.invalid_token_loader
def invalid_token_response(callback):
    return jsonify({
        'error': 'Invalid token',
        'description': 'Signature verification failed'
    }), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users:
        return jsonify({"msg": "User already exists"}), 400

    hashed_password = hash_password(password)
    users[username] = hashed_password

    return jsonify({"msg": "User registered successfully"}), 200

@app.route('/login', methods=['POST'])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400

    hashed_password = users.get(username)

    if hashed_password is None or not check_password(hashed_password, password):
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200



@app.route('/namespace/<key>', methods=['POST'])
@jwt_required()
def write_to_consul(key):
    try:
        # Extract JSON data from the request
        data = request.get_json()
        # key = data.get('key')
        # value = data.get('value')

        if not key or data is None:
            return jsonify({'error': 'Key and value are required'}), 400

        # Convert value to JSON string and write to Consul
        value_str = json.dumps(data)
        consul_client.kv.put(key, value_str)

        return jsonify({'message': 'Data written to Consul successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

@app.route('/consul/read/<key>', methods=['GET'])
@jwt_required()
def read_from_consul(key):
    try:
        index, data = consul_client.kv.get(key)

        if data is None:
            return jsonify({'error': 'Key not found'}), 404
        value = json.loads(data['Value'].decode('utf-8'))

        return jsonify({'key': key, 'value': value}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/acl/check/<doc>/<relation>/<user>', methods=['GET'])
@jwt_required()
def check_role(doc, relation, user):
    try:
        key = doc + '#' + relation + '@' + user
        value = 1

        if not key or value is None:
            return jsonify({'error': 'Key and value are required'}), 400
        
        # curr_data = redis_client.get(key)
        # if not curr_data is None:
        #     return jsonify({"authorized": True}), 200
        
        if check_for_curr_relations(doc, relation, user):
            return jsonify({"authorized": True}), 200
        else:
            return jsonify({"authorized": False}), 200
            
        # if check_for_curr_relations(doc, relation, user):
        #     return jsonify({'message': 'Data has been written already!'}), 200
        # else:
        #     redis_client.set(key, json.dumps(value))
        #     return jsonify({'message': 'Data written to Redis successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/acl', methods=['POST'])
@jwt_required()
def write_to_redis():
    try:
        data = request.get_json()
        doc = data.get('object')
        relation = data.get('relation')
        user = data.get('user')
        key = doc + '#' + relation + '@' + user
        value = 1

        if not key or value is None:
            return jsonify({'error': 'Key is required'}), 400
        
        if check_for_curr_relations(doc, relation, user, False):
            return jsonify({'message': 'Data has been written already!'}), 200
        else:
            redis_client.set(key, json.dumps(value))
            return jsonify({'message': 'Data written to Redis successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    

def read_all_keys_from_redis(doc, user, spec):
    roles = list(spec['relations'].keys())
    # keys = {'owner': doc + '#owner@' + user, 'editor': doc + '#editor@' + user,'viewer': doc + '#viewer@' + user}
    keys = {}
    for role in roles:
        keys[role] = doc + '#' + role + '@' + user
    for_check = []
    for key in keys.keys():
        # r.get('e').decode('utf-8')
        curr_data = redis_client.get(keys[key])
        # print(curr_data)
        if not curr_data is None:
            for_check.append(key)
    return for_check


def check_for_curr_relations(doc, relation, user, isCheck=True):
    index, data = consul_client.kv.get(doc)

    if data is None:
        return False
    value = json.loads(data['Value'].decode('utf-8'))
    for_check = read_all_keys_from_redis(doc, user, value)
    # logger.info(for_check)
    for key in for_check:
        if not isCheck:
            delete_if_lower_rights(relation, value, key, doc, user)
        if relation == key:
            return True
        if check_computed_userset(relation, value, key):
            return True
    return False
        

def check_computed_userset(relation, spec, curr_relation):
    
    try:
        usersets = spec['relations'][relation]['union']
        for obj in usersets:
            try:
                curr_obj = obj['computed_userset']
                print(curr_obj)
                if not curr_obj is None:
                    if curr_obj['relation'] == curr_relation or check_computed_userset(curr_obj['relation'], spec, curr_relation):
                        return True
            except:
                pass
        return False
    except:
        return False
        # try:
        #     usersets = spec['relations'][curr_relation]['union']
        #     for obj in usersets:
        #         try:
        #             curr_obj = obj['computed_userset']
        #             # print(curr_obj)
        #             if not curr_obj is None:
        #                 if curr_obj['relation'] == relation:
        #                     redis_client.delete(doc + '#' + curr_relation + '@' + user)
        #                     return False
        #             return False
        #         except:
        #             pass
        # except: 
        #     return False
        
def delete_if_lower_rights(relation, spec, curr_relation, doc, user):
    try:
        usersets = spec['relations'][curr_relation]['union']
        for obj in usersets:
            try:
                curr_obj = obj['computed_userset']
                # print(curr_obj)
                if not curr_obj is None:
                    if curr_obj['relation'] == relation:
                        redis_client.delete(doc + '#' + curr_relation + '@' + user)
                        # return False
                # return False
            except:
                pass
    except: 
        pass       # return False
        

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    context = (cert_path, key_path)
    app.run(port=port, ssl_context=context)
