import os
import re
import shutil
import subprocess
from zipfile import ZipFile
from flask import Flask, Response
from flask import request, send_file
from flask import render_template
from flask import jsonify

# Flask config
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = app.instance_path
app.secret_key = 'Junk. Or should it be generated?'

def __corelate_key(key, certs):
    for cert in certs:
        if key.get_pubkey() == cert.get_pubkey():
            key.set_cert(cert)

def __corelate_certs(certs):
    mapOfSubjectToCert = {}
    mapOfIssuerToCert = {}
    for cert in certs:
        mapOfSubjectToCert[cert.get_subject()] = cert
        # multiple certs can have same issuer
        if cert.get_issuer() in mapOfIssuerToCert:
            mapOfIssuerToCert[cert.get_issuer()].append(cert)
        else:
            mapOfIssuerToCert[cert.get_issuer()] = [ cert ]
    for issuer in mapOfIssuerToCert:
        if issuer in mapOfSubjectToCert:
            issuer_cert = mapOfSubjectToCert[issuer]
            subject_certs = mapOfIssuerToCert[issuer]
            for subject_cert in subject_certs:
                subject_cert.set_issuer_cert(issuer_cert)

def __create_certs(key_filename, pem_filenames, password):
    key = ClientKey(key_filename, password)
    certs = []
    for filename in pem_filenames:
        cert = CertInfo(filename)
        certs.append(cert)
    __corelate_key(key, certs)
    __corelate_certs(certs)
    return (key, certs)

@app.route("/")
def home():
    return render_template('converter.html')

@app.route('/status', methods=['GET'])
def status():
    global pem_filenames, key_filename
    result = { 'keyCount': 1 if key_filename != None else 0, 'pemCount': len(pem_filenames) }
    return jsonify(result)

@app.route('/clear', methods=['POST'])
def clear():
    global pem_filenames, key_filename
    pem_filenames = []
    key_filename = None
    # Delete and create instance directory
    if os.path.exists(app.instance_path):
        shutil.rmtree(app.instance_path)
    os.mkdir(app.instance_path)
    return "cleared"

@app.route('/upload', methods=['POST'])
def upload():
    global pem_filenames, key_filename
    uploaded_files = request.files.getlist("file[]")
    if uploaded_files is None:
        flash('No file part')
        return redirect(request.url)
    for file in uploaded_files:
        filename = file.filename
        if filename.endswith('.cer') or filename.endswith('.pem'):
            if filename not in pem_filenames:
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                pem_filenames.append(filename)
        if filename.endswith('.key'):
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            key_filename = filename
    return status()
    
def __create_keycert(key, password):
    cert_chain_pem = os.path.join(app.config['UPLOAD_FOLDER'], 'cert_chain.pem')
    if os.path.exists(cert_chain_pem):
        os.remove(cert_chain_pem)
    out = open(cert_chain_pem, "w")
    command = 'cat'
    cert = key.get_cert()
    while cert is not None:
        command += ' ' + cert.get_abs_filename()
        if cert == cert.get_issuer_cert():
            break;
        cert = cert.get_issuer_cert()
    print('command=' + command)
    subprocess.run(command.split(), stdout=out)
    out.close()
    
    keycert_p12 = os.path.join(app.config['UPLOAD_FOLDER'], 'keycert.p12')
    if os.path.exists(keycert_p12):
        os.remove(keycert_p12)
    command = 'openssl pkcs12 -export -passin pass:%s -passout pass:%s -in %s -inkey %s -out %s' % (password, password, cert_chain_pem, key.get_abs_filename(), keycert_p12)
    print('command=' + command)
    subprocess.run(command.split())

    keycert_jks = os.path.join(app.config['UPLOAD_FOLDER'], 'keycert.jks')
    if os.path.exists(keycert_jks):
        os.remove(keycert_jks)
    command = 'keytool -importkeystore -srckeystore %s -destkeystore %s -srcstoretype PKCS12 -srcstorepass %s -deststorepass %s' % (keycert_p12, keycert_jks, password, password)
    print('command=' + command)
    subprocess.run(command.split())
    return keycert_jks

def __create_trust(certs, password):
    trust_jks = os.path.join(app.config['UPLOAD_FOLDER'], 'trust.jks')
    if os.path.exists(trust_jks):
        os.remove(trust_jks)
    for cert in certs:
        command = 'keytool -import -noprompt -keystore %s -storepass %s -alias %s -file %s' % (trust_jks, password, cert.get_filename(), cert.get_abs_filename())
        subprocess.run(command.split())
    return trust_jks

@app.route('/downloadZip', methods=['POST'])
def downloadZip():
    global pem_filenames, key_filename
    password = request.values['password']
    (key, certs) = __create_certs(key_filename, pem_filenames, password)
    keycert_jks = __create_keycert(key, password)
    trust_jks = __create_trust(certs, password)
    jks_zip = os.path.join(app.config['UPLOAD_FOLDER'], 'jks.zip')
    if os.path.exists(jks_zip):
        os.remove(jks_zip)
    with ZipFile(jks_zip, 'w') as zip:
        zip.write(keycert_jks, os.path.basename(keycert_jks))
        zip.write(trust_jks, os.path.basename(trust_jks))
    return send_file(jks_zip, attachment_filename='jks.zip', as_attachment=True)

class ClientKey:
    def __init__(self, filename, password):
        self.filename = filename
        self.password = password
        self.abs_filename = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        self.pubkey = self.__run('openssl pkey -pubout -outform pem -passin pass:%s -in %s' % (password, self.abs_filename))
        self.cert = None

    def __run(self, command):
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        return result.stdout.decode('utf-8')

    def get_filename(self):
        return self.filename

    def get_abs_filename(self):
        return self.abs_filename

    def get_pubkey(self):
        return self.pubkey

    def get_cert(self):
        return self.cert
    
    def set_cert(self, cert):
        self.cert = cert

class CertInfo:
    def __init__(self, filename):
        self.filename = filename
        self.abs_filename = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        subject = self.__run('openssl x509 -noout -subject -in %s' % self.abs_filename)
        self.subject = re.sub('^.*?/', '', subject).strip()
        issuer = self.__run('openssl x509 -noout -issuer -in %s' % self.abs_filename)
        self.issuer = re.sub('^.*?/', '', issuer).strip()
        self.pubkey = self.__run('openssl x509 -pubkey -noout -outform pem -in %s' % self.abs_filename)
        self.issuer_cert = None

    def __run(self, command):
        result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        return result.stdout.decode('utf-8')
    
    def get_filename(self):
        return self.filename
    
    def get_abs_filename(self):
        return self.abs_filename

    def get_pubkey(self):
        return self.pubkey
    
    def get_subject(self):
        return self.subject

    def get_issuer(self):
        return self.issuer

    def get_issuer_cert(self):
        return self.issuer_cert

    def set_issuer_cert(self, cert):
        self.issuer_cert = cert
        
    def __repr__(self):
        message = ''
        message += 's=' + self.subject + ' i=' + self.issuer
        if self.get_issuer_cert() is not None:
            message += ' i-file=' + self.get_issuer_cert().get_filename()
        return message


if __name__ == '__main__':
    # Clear first
    clear()
    app.run(host='0.0.0.0', port=80)
