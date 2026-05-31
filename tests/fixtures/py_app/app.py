from flask import Flask, request
from flask_jwt_extended import jwt_required, get_jwt_identity

app = Flask(__name__)


@app.route('/api/users/<id>', methods=['GET'])
@jwt_required()
def get_user(id):
    tenantId = request.args.get('tenantId')
    return {'id': id, 'tenant': tenantId}
