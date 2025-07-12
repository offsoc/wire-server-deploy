from flask import Flask, jsonify, request, make_response, abort
import logging
from functools import wraps
import time
import base64
import re

app = Flask(__name__)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

rate_limit = {}
RATE_LIMIT = 100
RATE_PERIOD = 60

def rate_limiter(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = request.remote_addr
        now = int(time.time())
        window = now // RATE_PERIOD
        key = f"{ip}:{window}"
        count = rate_limit.get(key, 0)
        if count >= RATE_LIMIT:
            logging.warning(f"Rate limit exceeded for {ip}")
            abort(429)
        rate_limit[key] = count + 1
        return func(*args, **kwargs)
    return wrapper

@app.before_request
def log_request():
    logging.info(f"{request.remote_addr} {request.method} {request.path}")

def gen_dns_token():
    return base64.urlsafe_b64encode(b"mocked-dns-token").rstrip(b'=').decode()

def mock_domain_registration(domain):
    return {
        "domain": domain,
        "authorizedTeam": "mock-team-id",
        "domainRedirect": "None",
        "teamInvite": "Allowed",
        "dnsVerificationToken": gen_dns_token()
    }

# 1. create-verification-token
@app.route('/i/create-verification-token', methods=['POST'])
@rate_limiter
def create_verification_token():
    return jsonify(gen_dns_token())

# 2. verify-domain-token
@app.route('/i/verify-domain-token/<domain>/<dns_token>', methods=['POST'])
@rate_limiter
def verify_domain_token(domain, dns_token):
    if not re.match(r"^[a-zA-Z0-9.\-]+$", domain):
        abort(400)
    if not re.match(r"^[A-Za-z0-9_\-]+$", dns_token):
        abort(400)
    return jsonify(True)

# 3. domain-registration lock/unlock/preauthorize/delete/unauthorized/update
@app.route('/i/domain-registration/<domain>/lock', methods=['POST'])
@rate_limiter
def domain_registration_lock(domain):
    return '', 204

@app.route('/i/domain-registration/<domain>/unlock', methods=['POST'])
@rate_limiter
def domain_registration_unlock(domain):
    return '', 204

@app.route('/i/domain-registration/<domain>/preauthorize', methods=['POST'])
@rate_limiter
def domain_registration_preauthorize(domain):
    return '', 204

@app.route('/i/domain-registration/<domain>/delete', methods=['POST'])
@rate_limiter
def domain_registration_delete(domain):
    return '', 204

@app.route('/i/domain-registration/<domain>/unauthorized', methods=['POST'])
@rate_limiter
def domain_registration_unauthorized(domain):
    return '', 204

@app.route('/i/domain-registration/<domain>/update', methods=['POST'])
@rate_limiter
def domain_registration_update(domain):
    return '', 204

# 4. 获取域名注册信息
@app.route('/i/get-domain-registration/<domain>', methods=['GET'])
@rate_limiter
def get_domain_registration(domain):
    return jsonify(mock_domain_registration(domain))

# 5. 获取所有注册域名
@app.route('/i/get-all-registered-domains', methods=['GET'])
@rate_limiter
def get_all_registered_domains():
    return jsonify([mock_domain_registration("mockdomain.com")])

# 6. 团队授权
@app.route('/i/authorize-team', methods=['POST'])
@rate_limiter
def authorize_team():
    return '', 204

# 7. 验证挑战
@app.route('/i/verify-challenge', methods=['POST'])
@rate_limiter
def verify_challenge():
    return jsonify(True)

# 8. 更新团队邀请
@app.route('/i/update-team-invite', methods=['POST'])
@rate_limiter
def update_team_invite():
    return '', 204

# 9. 获取公开域名注册信息
@app.route('/i/get-domain-registration-public', methods=['GET'])
@rate_limiter
def get_domain_registration_public():
    return jsonify(mock_domain_registration("mockdomain.com"))

# 10. 健康检查接口
@app.route('/i/status', methods=['GET', 'POST'])
def status():
    return '', 200

# 11. SSO/OAuth/SCIM等企业功能相关接口（如有调用可补充）
@app.route('/i/sso/metadata', methods=['GET'])
@rate_limiter
def sso_metadata():
    # 返回模拟SAML元数据
    return make_response("<xml>mock-sso-metadata</xml>", 200, {'Content-Type': 'application/xml'})

@app.route('/i/sso/initiate-login', methods=['POST'])
@rate_limiter
def sso_initiate_login():
    return jsonify({"redirect": "https://mock-sso-redirect"})

@app.route('/i/sso/finalize-login', methods=['POST'])
@rate_limiter
def sso_finalize_login():
    return jsonify({"result": "success"})

@app.route('/i/oauth/token', methods=['POST'])
@rate_limiter
def oauth_token():
    return jsonify({
        "access_token": "mocked-access-token",
        "token_type": "Bearer",
        "expires_in": 3600
    })

# 12. 拒绝未定义的路径和方法
@app.errorhandler(404)
def not_found(e):
    logging.warning(f"404 Not Found: {request.path}")
    return jsonify({"error": "Not Found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    logging.warning(f"405 Method Not Allowed: {request.method} {request.path}")
    return jsonify({"error": "Method Not Allowed"}), 405

@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({"error": "Too Many Requests"}), 429

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
