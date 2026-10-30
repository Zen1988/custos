"""CUSTOS visual prototype. NO live API, authentication, or authorization."""
from flask import Flask, render_template
app=Flask(__name__)
@app.get('/')
def index():
    vms=[
      {'name':'APP-WEB-01','provider':'VMware','state':'Running','cpu':4,'ram':16},
      {'name':'APP-DB-01','provider':'Nutanix','state':'Running','cpu':8,'ram':32},
      {'name':'APP-TEST-01','provider':'VMware','state':'Stopped','cpu':2,'ram':8},
    ]
    return render_template('index.html',vms=vms)
if __name__=='__main__':
    app.run(host='127.0.0.1',port=8080,debug=False)
