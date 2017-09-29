from flask import Flask, request
from flask_pam import Auth
from flask_pam.token_storage import DictStorage
from flask_pam.token import JWT
from datetime import datetime
import json
import www_config
import os                                                                  
import stat

app = Flask(__name__)
app.secret_key = 'test_secret_key'
auth = Auth(DictStorage, JWT, 300, 600, app)

header = '''source /opt/vyatta/etc/functions/script-template
OPRUN=/opt/vyatta/bin/vyatta-op-cmd-wrapper                
CFGRUN=/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper                             
API=/bin/cli-shell-api                                                     
shopt -s expand_aliases                                                    
'''

@app.route('/')
def index():
    return json.dumps({'status': True, 'data': None})

@app.route('/authenticate', methods=['POST', 'GET'])
def authenticate():
    if request.method == 'POST':
        if not (request.form['username'] and request.form['password']):
            return json.dumps({
                'status': False,
                'errors': [
                    'username or password is not set!'
                ]
            })

        username = request.form['username'].encode('ascii')
        password = request.form['password'].encode('ascii')

        result = auth.authenticate(username, password,
                                   ip=request.remote_addr)
                                   

        role = None
        user_groups = auth.get_groups(username)
        for group in www_config.groups:
            if group in user_groups:
                role = group
                break

        if result[0]:
            return json.dumps({
                'status': True,
                'data': [
                    {
                        'type': 'tokens',
                        'id': result[1].generate(),
                        'attributes': {
                            'expire': int(result[1].expire.strftime('%s')),
                        }
                    },
                    {
                        'type': 'refresh_tokens',
                        'id': result[2].generate(),
                        'attributes': {
                            'expire': int(result[2].expire.strftime('%s')),
                        }
                    },
                    {
                        'type': 'roles',
                        'id': role,
                    }
                ]
            })

    return json.dumps({
        'status': False,
        'errors': [
            'authentication faild!',
        ]
    })

@app.route('/protected', methods=['POST', 'GET'])
@auth.auth_required
def protected():
    return json.dumps({
        'status': True,
        'data': None,
    })

@app.route('/set', methods=['POST', 'GET'])
@auth.group_required("admin")
def gprotected1():

    path = '/tmp/exec'                                                
    f= open(path ,"w+")                                                    
    f.write(header)                                                        
    st = os.stat(path)                                     
    os.chmod(path, st.st_mode | stat.S_IEXEC)
 
    return json.dumps({
        'status': True,
        'data': {
            'id': 'groups',
            'type': "admin"
        }
    })


if __name__ == '__main__':
    app.debug = True
    app.run()
