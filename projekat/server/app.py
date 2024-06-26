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

cert_path = os.getenv('CERT_PATH')
key_path = os.getenv('KEY_PATH')
port = int(os.getenv('FLASK_PORT', 5000))


# Initialize Consul client
consul_client = consul.Consul(host='localhost', port=8500)
redis_client = redis.Redis(host='localhost', port=6379, db=0)


@app.route('/namespace/<key>', methods=['POST'])
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
