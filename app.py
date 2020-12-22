from flask import Flask, request
from coding import Reputation
app = Flask(__name__)


@app.route('/virustotal',methods=["GET"])
def elementor_api():
    obj = Reputation()
    json_req = request.json
    if json_req.get('url'):
        return obj.query_url(json_req.get("url"))



if __name__ == "__main__":
    app.run(debug=True,port=5000)