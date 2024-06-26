import consul
import json
import redis
import logging

# Initialize Consul client
consul_client = consul.Consul(host='localhost', port=8500)
redis_client = redis.Redis(host='localhost', port=6379, db=0)



def read_all_keys_from_redis(doc, user, spec):
    # keys = {'owner': doc + '#owner@' + user, 'editor': doc + '#editor@' + user,'viewer': doc + '#viewer@' + user}
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


def check_for_curr_relations(doc, relation, user):
    index, data = consul_client.kv.get(doc)

    if data is None:
        return False
    value = json.loads(data['Value'].decode('utf-8'))
    for_check = read_all_keys_from_redis(doc, user, value)
    # logger.info(for_check)
    for key in for_check:
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
                    print(relation)
                    print(curr_relation)
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

if __name__=='__main__':
    key = "doc:readme#viewer@user:alice"
    value = 1

    if not key or value is None:
        print('error' + 'Key and value are required')
    
    if check_for_curr_relations('doc:readme', 'viewer', 'user:alice'):
        print('message' + 'Data has been written already!')
    else:
        redis_client.set(key, json.dumps(value))
        print('upisaaaoo')
        # return jsonify({'message': 'Data written to Redis successfully'}), 200