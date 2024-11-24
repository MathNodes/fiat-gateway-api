import pwd
import os
import jwt
import time
import stripe
import pexpect

from datetime import datetime

from flaskext.mysql import MySQL
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from passlib.apps import custom_app_context as pwd_context
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

from urllib.parse import urlparse
import urllib
import ipaddress
import socket

import scrtxxs


VERSION=20240430.005001

app = Flask(__name__)
mysql = MySQL()
mysql.init_app(app)

 
stripe.api_key = scrtxxs.StripeSCRTKey

HotWalletAddress = scrtxxs.WalletAddress
keyring_passphrase = scrtxxs.HotWalletPW
MAX_SPEND = scrtxxs.MAX_SPEND

DBdir = '/home/' + str(pwd.getpwuid(os.getuid())[0]) + '/dbs'
WalletLogDIR = '/home/' + str(pwd.getpwuid(os.getuid())[0]) + '/Logs'
DBFile = 'sqlite:///' + DBdir + '/dvpn_stripe.sqlite'


# SQLAlchemy Configurations
app.config['SECRET_KEY'] = scrtxxs.SQLAlchemyScrtKey
app.config['SQLALCHEMY_DATABASE_URI'] = DBFile
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFCATIONS'] = False

# MySQL configurations
app.config['MYSQL_DATABASE_USER'] = scrtxxs.MySQLUsername
app.config['MYSQL_DATABASE_PASSWORD'] = scrtxxs.MySQLPassword
app.config['MYSQL_DATABASE_DB'] = scrtxxs.MySQLDB
app.config['MYSQL_DATABASE_HOST'] = 'localhost'


db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(128))

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'],
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])
 
@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})

@app.route('/api/users/<int:id>')
def get_user(id): 
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})

@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})

@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404</h1><p>The resource could not be found.</p>", 404

@app.route('/api/ping', methods=['POST'])
def meile_ping():
    uuid         = request.json.get('uuid')
    OS           = request.json.get('os')
    user_ip      = request.remote_addr
    
    insquery = 'INSERT IGNORE INTO meileping (uuid, timestamp, os, ip) VALUES ("%s", NOW(), "%s", "%s")' % (uuid, OS, user_ip)
    
    UpdateDBTable(insquery)
    return {'status' : 200}

@app.route('/api/rating', methods=['POST'])
def AddRating():
    try:
        meile_uuid   = request.json.get('uuid')
        node_address = request.json.get('address')
        rating       = request.json.get('rating')
        UpdateRatingsDB(meile_uuid, node_address, rating)
    except Exception as e:
        return {'status' : 404}
        print(str(e))
    
    return {'status' : 200} 

@app.route('/api/nodescores', methods=['GET'])
def GetNodeRatings():
    conn = mysql.connect()
    cur  = conn.cursor()
    
    query = "SELECT * FROM ratings_nodes"
    cur.execute(query)
    
    return jsonify(data=cur.fetchall())
  
@app.route('/api/nodelocations', methods=['GET'])
def GetNodeLocations():
    conn = mysql.connect()
    cur  = conn.cursor()
    
    query = "SELECT * FROM node_cities"
    cur.execute(query)
    
    return jsonify(data=cur.fetchall())

@app.route('/api/nodeformula', methods=['GET'])
def GetFormula():
    conn = mysql.connect()
    cur  = conn.cursor()
    
    query = "SELECT * FROM node_formula"
    cur.execute(query)
    
    return jsonify(data=cur.fetchall())


@app.route('/api/nodetypes', methods=['GET'])
def GetNodeType():
    conn = mysql.connect()
    cur  = conn.cursor()
    
    query = "SELECT * FROM node_score"
    cur.execute(query)
    
    return jsonify(data=cur.fetchall())

@app.route('/api/nodetypesip', methods=['GET'])
def GetNodeTypeIP():
    conn = mysql.connect()
    cur  = conn.cursor()
    
    query = "SELECT * FROM node_score"
    cur.execute(query)
    
    data=cur.fetchall()
    #print(data)
    newdata = []
    
    for d in data:
        #print(d)
        d_pip = ()
        address = d[0]
        query = f"SELECT remote_url FROM node_uptime WHERE node_address = '{address}';"
        cur.execute(query)
        rurl = cur.fetchone()
        #print(rurl)
        try: 
        #    host, port = urlparse(rurl[0]).netloc.split(":")
            result = urllib.parse.urlsplit('//' + rurl[0])
        except TypeError:
            d_pip = d + ("",)
            newdata.append(d_pip)
            continue
        try: 
            ip = ipaddress.ip_address(result.hostname)
        except ValueError:
            try:
                ip = socket.gethostbyname(result.hostname)
            except socket.gaierror:
                d_pip = d + ("",)
                newdata.append(d_pip)
                continue
            
        d_pip = d + (str(ip),)
        newdata.append(d_pip)
        
    return jsonify(data=newdata)

@app.route('/api/cachelist', methods=['GET'])
def GetCacheList():

    query = f"SELECT * FROM meile_cache_servers;"
    
    conn = mysql.connect()
    c = conn.cursor()
    
    c.execute(query)

    rows = c.fetchall()
    columns = [desc[0] for desc in c.description]
    result = []
    for row in rows:
        row = dict(zip(columns, row))
        result.append(row)

    try: 
        return jsonify(result)
    except Exception as e:
        print(str(e))
        abort(404)

@app.route('/api/btcpay', methods=['GET'])
@auth.login_required
def GetBTCPayClient():
    conn = mysql.connect()
    cur  = conn.cursor()
    
    query = "SELECT btcpay_client FROM btcpay WHERE id = 2;" # Normally is id=1, adjust as needed
    cur.execute(query)
    
    data=cur.fetchone()
    print(data)
    
    return data[0]

@app.route('/api/maxspend', methods=['GET'])
def GetMaxSpendAmount():   
    msdict = {'max_spend' : MAX_SPEND}
    
    return jsonify(msdict)
    
@app.route('/api/minprices', methods=['GET'])
def GetMonthlyMinPrices():
    with open('min_gigabyte_prices', 'r') as tdata:
        data = tdata.readlines()
        
    with open('min_hourly_prices', 'r') as hdata:
        data2 = hdata.readlines()
        
    gbdata = {}
    hrdata = {}
    for d in data:
        coin,muprice = d.rstrip().split(',')
        gbdata[coin] = muprice
        
    for d in data2:
        coin,muprice = d.rstrip().split(',')
        hrdata[coin] = muprice
        
    PRICE_DATA = {'MinGB' : gbdata, 'MinHr' : hrdata}
    
    return jsonify(PRICE_DATA)
        
         
@app.route('/api/tt', methods=['POST'])
@auth.login_required
def TransferTokens():
    #DVPNQtys = [1000, 2000, 5000, 10000]
    token = 'dvpn'
    dvpn_address = request.json.get('address')
    stripe_id    = request.json.get('id')
    dvpn_qty     = request.json.get('qty')
    try:
        token        = request.json.get('token')
    except:
        token = 'dvpn'
    user_ip      = request.remote_addr
    ExceptionLogFile = open(os.path.join(WalletLogDIR, "exceptions.log"), 'a+')
    StatusDict = {'message' : None, 'tx' : None}
    TransferLogFile = os.path.join(WalletLogDIR, "dvpn_transfer_status.log")
    
    ts = datetime.now()
    
    
    Blacklist = ParseBlacklist()
    
    strts = ts.strftime("%d-%b-%Y (%H:%M:%S.%f)")
    ofile = open(TransferLogFile, 'a+')
    ofile.write('-----------------------------%s--------------------------------\n' % strts)
    #if int(dvpn_qty) in DVPNQtys:
    if VerifySuccessfulPayment(stripe_id):
        print("Stripe ID: %s" % stripe_id)
        ofile.write("Stripe ID: %s\n" % stripe_id)
        print("Beginnning Transfer of %s%s to %s\n" % (dvpn_qty,token,dvpn_address))
        ofile.write("Beginnning Transfer of %s%s to %s" % (dvpn_qty,token,dvpn_address))
        try: 
            if dvpn_address in Blacklist:
                StatusDict['message'] = "Due to suspicious activity, the funds were not sent. Please contact support@mathnodes.com to receive further information and processing of a refund."
                ofile.write(StatusDict['message'] + '\n')
                ofile.write('------------------------------------------------------------------------------\n')
                ofile.close()
                print('-------------------------------------SUS AS FUC---------------------------------------------')
                print(StatusDict['message'])
                print('-------------------------------------SUS AS FUC---------------------------------------------')
                UpdateDB(stripe_id, dvpn_address, user_ip, "None", StatusDict['message'])
                return jsonify(StatusDict)
            
            if ComputePurchaseFrequency(dvpn_address):
                StatusDict['message'] = "Due to suspicious activity, the funds were not sent. Please contact support@mathnodes.com to receive further information and processing of a refund."
                ofile.write(StatusDict['message'] + '\n')
                ofile.write('------------------------------------------------------------------------------\n')
                ofile.close()
                print('-------------------------------------SUS AS FUC---------------------------------------------')
                print(StatusDict['message'])
                print('-------------------------------------SUS AS FUC---------------------------------------------')
                UpdateDB(stripe_id, dvpn_address, user_ip, "None", StatusDict['message'])
                return jsonify(StatusDict)
            
            if StripeIDUsed(stripe_id):
                StatusDict['message'] = "This Stripe ID was already used to processes a transaction. Cannot transfer again using same StripeID."
                ofile.write(StatusDict['message'] + '\n')
                ofile.write('------------------------------------------------------------------------------\n')
                ofile.close()
                print('-------------------------------------SUS AS FUC---------------------------------------------')
                print(StatusDict['message'])
                print('-------------------------------------SUS AS FUC---------------------------------------------')
                UpdateDB(stripe_id, dvpn_address, user_ip, "None", StatusDict['message'])
                return jsonify(StatusDict)
            
            state, tx = TransferCoinsToPayee(dvpn_address, dvpn_qty, token)
            print("Transfer of tokens")
            if state:
                StatusDict['message'] = "%s%s transfered from %s to %s" % (dvpn_qty, token, HotWalletAddress, dvpn_address)
                StatusDict['tx'] = tx
                ofile.write(StatusDict['message'] + '\n')
                ofile.write('------------------------------------------------------------------------------\n')
                ofile.close()
                UpdateDB(stripe_id, dvpn_address, user_ip, tx,  "SUCCESSFUL")
                return jsonify(StatusDict)
            else:
                print("Something went wrong")
                StatusDict['message'] = "Something went wrong. Please contact support@mathnodes.com for more information."
                UpdateDB(stripe_id, dvpn_address, user_ip, tx, StatusDict['message'])
                ofile.write(StatusDict['message'] + '\n')
                ofile.write('------------------------------------------------------------------------------\n')
                ofile.close()
                return jsonify(StatusDict)
        except Exception as e:
            ExceptionLogFile.write(str(e) + '\n')
            ExceptionLogFile.close()
            StatusDict['message'] = str(e)
            UpdateDB(stripe_id, dvpn_address, user_ip, 'none', StatusDict['message'])
            ofile.write(StatusDict['message']+ '\n')
            ofile.write('------------------------------------------------------------------------------\n')
            ofile.close()
            return jsonify(StatusDict)
    else:
        StatusDict['message'] = "Payment not marked as paid."
        ofile.write(StatusDict['message']+ '\n')
        ofile.write('------------------------------------------------------------------------------\n')
        ofile.close()
        UpdateDB(stripe_id, dvpn_address, user_ip, 'none' , StatusDict['message'])
        return jsonify(StatusDict)
    '''    
    else:
        StatusDict['message'] = "QTY not supported. Erroneous amount "
        ofile.write(StatusDict['message']+ '\n')
        ofile.write('------------------------------------------------------------------------------\n')
        ofile.close()
        UpdateDB(stripe_id, dvpn_address, user_ip,'none', StatusDict['message'])
        return jsonify(StatusDict)
    '''
    
def UpdateRatingsDB(uuid, address, rating):
        insquery = '''
                    INSERT IGNORE INTO ratings_user (uuid, node_address, rating, timestamp)
                    VALUES ("%s", "%s", %d, NOW());
                    ''' % (uuid, address, rating )
                    
        UpdateDBTable(insquery) 
           
def UpdateDB(stripe_id, dvpn_address, ip, tx, message):
        insquery = '''
                    INSERT IGNORE INTO stripe (stripe_id, receiving_address, ip_address, status, sale_date, TX)
                    VALUES ("%s", "%s", "%s", "%s", NOW(), "%s");
                    ''' % (stripe_id, dvpn_address, ip, message, tx)
                    
        UpdateDBTable(insquery)

def UpdateDBTable(query):
    conn = mysql.connect()
    cursor = conn.cursor()
    cursor.execute(query)
    conn.commit()

def VerifySuccessfulPayment(stripe_id):
    payment_retrieval = stripe.Charge.retrieve(stripe_id,)
    return payment_retrieval['paid']
    
def TransferCoinsToPayee(address, qty, token):
    SATOSHI = 1000000
    IBC = {'dvpn' : 'udvpn', 
           'scrt' : 'ibc/31FEE1A2A9F9C01113F90BD0BBCCE8FD6BBB8585FAF109A2101827DD1D5B95B8', 
           'dec'  : 'ibc/B1C0DDB14F25279A2026BC8794E12B259F8BDA546A3C5132CCAEE4431CE36783'}
    DENOM = IBC['dvpn']
    
    for key,value in IBC.items():
        if key == token:
            DENOM = value
    
    CoinAmt = str(int(SATOSHI)*int(qty)) + DENOM
    WalletLogFile = os.path.join(WalletLogDIR, "dvpn_stripe.log")
        
    transfer_cmd = "/home/sentinel/sentinelhub tx bank send --gas auto --gas-prices 0.2udvpn --gas-adjustment 2.0 --yes %s %s %s --node https://rpc.mathnodes.com:443" % (HotWalletAddress, address, CoinAmt)
    print(transfer_cmd)
    try: 
        ofile = open(WalletLogFile, 'ab+')
        
        child = pexpect.spawn(transfer_cmd)
        child.logfile = ofile
        
        child.expect("Enter .*")
        child.sendline(keyring_passphrase)
        child.expect(pexpect.EOF)
        
        
        ofile.flush()
        ofile.close()
        ofile.close()
        with open(WalletLogFile ,'r+') as rfile:
            last_line = rfile.readlines()[-1]
            if 'txhash' in last_line:
                tx = last_line.split(':')[-1].rstrip().lstrip()
                print(tx)
            else:
                tx = 'none'
        
        rfile.close()
    except Exception as e:
        print(str(e))
        return (False,'NONE')
    
    return (True,tx)
    
def ParseBlacklist():    
    with open('blacklist', 'r') as blfile:
        data = blfile.readlines()
        
    newdata = []
    for d in data:
        d = d.replace('\n', '')
        newdata.append(d)
    print("Blacklist: %s" % newdata)
    return newdata

def AddToBlacklist(address):
    
    blm = open('blacklist' ,'a+')
    
    blm.write(address + '\n')
    blm.flush()
    blm.close()

'''
To be written by the adopter of this fiat gateway
Most likely use AddToBlacklist if their purchase
frequency meets your specific threshold. 
'''
def ComputePurchaseFrequency(address):
    pass

def StripeIDUsed(stripe_id):
    q = f'SELECT stripe_id FROM stripe WHERE stripe_id = "{stripe_id}"'
    
    conn = mysql.connect()
    c    = conn.cursor()
    c.execute(q)
    
    results = c.fetchall()
    print(len(results))
    if len(results) > 0:
        return True
    
    return False
   
db.create_all() 
