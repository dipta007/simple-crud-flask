from flask import Flask
from flask import jsonify
from flask import request
from flask_pymongo import PyMongo
from controller import *
from flask_jwt_extended import (JWTManager, create_access_token, create_refresh_token, jwt_required,
                                jwt_refresh_token_required, get_jwt_identity)
from flask_bcrypt import Bcrypt
from Schema.User import validate_user

app = Flask(__name__)
app.json_encoder = JSONEncoder

app.config['JWT_SECRET_KEY'] = "asdfqwerty"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(days=1)

app.config['MONGO_DBNAME'] = 'amazon'
app.config['MONGO_URI'] = 'mongodb://localhost:27017/amazon'

flask_bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mongo = PyMongo(app)


@app.route('/', methods=['GET'])
def hello_world():
    return 'Hello World!'


@app.route('/users', methods=['GET'])
@jwt_required
def get_all_users():
    star = mongo.db.users
    output = []
    for s in star.find():
        if s.get("name") and s.get("email"):
            output.append({'name': s['name'], 'email': s['email']})
    return jsonify({'result': output})


@app.route("/user", methods=['GET', 'POST', 'DELETE', 'PATCH'])
@jwt_required
def user():
    if request.method == 'GET':
        query = request.args
        data = mongo.db.users.find_one(query)
        del data['password']
        return jsonify(data), 200

    data = request.get_json()
    if request.method == 'DELETE':
        if data.get('email'):
            db_response = mongo.db.users.delete_one({'email': data['email']})
            if db_response.deleted_count == 1:
                response = {'ok': True, 'message': 'record deleted'}
            else:
                response = {'ok': True, 'message': 'no record found'}
            return jsonify(response), 200
        else:
            return jsonify({'ok': False, 'message': 'Bad request parameters!'}), 400

    if request.method == 'PATCH':
        if data.get('query', {}) != {}:
            mongo.db.users.update_one(
                data['query'], {'$set': data.get('payload', {})})
            return jsonify({'ok': True, 'message': 'record updated'}), 200
        else:
            return jsonify({'ok': False, 'message': 'Bad request parameters!'}), 400


@app.route('/register', methods=['POST'])
def register():
    ''' register user endpoint '''
    data = validate_user(request.get_json())
    if data['ok']:
        data = data['data']
        data['password'] = flask_bcrypt.generate_password_hash(data['password'])
        mongo.db.users.insert_one(data)
        return jsonify({'ok': True, 'message': 'User created successfully!'}), 200
    else:
        return jsonify({'ok': False, 'message': 'Bad request parameters: {}'.format(data['message'])}), 400


@app.route('/auth', methods=['POST'])
def auth_user():
    ''' auth endpoint '''
    data = validate_user(request.get_json())
    if data['ok']:
        data = data['data']
        user = mongo.db.users.find_one({'email': data['email']}, {"_id": 0})
        if user and flask_bcrypt.check_password_hash(user['password'], data['password']):
            del user['password']
            access_token = create_access_token(identity=data)
            refresh_token = create_refresh_token(identity=data)
            user['token'] = access_token
            user['refresh'] = refresh_token
            return jsonify({'ok': True, 'data': user}), 200
        else:
            return jsonify({'ok': False, 'message': 'invalid username or password'}), 401
    else:
        return jsonify({'ok': False, 'message': 'Bad request parameters: {}'.format(data['message'])}), 400


@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    ''' refresh token endpoint '''
    current_user = get_jwt_identity()
    ret = {
        'token': create_access_token(identity=current_user)
    }
    return jsonify({'ok': True, 'data': ret}), 200


if __name__ == '__main__':
    app.run(debug=True)
