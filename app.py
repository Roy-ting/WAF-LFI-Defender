from flask import Flask, request, jsonify, Response
import requests
from detector import FileInclusionDetector

app = Flask(__name__)

# 靶场地址（DVWA 跑在 8080 端口）
TARGET_URL = "http://127.0.0.1:8080"

# 实例化检测器
detector = FileInclusionDetector()

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    url = f"{TARGET_URL}/{path}"
    query_params = request.args.to_dict()
    form_data = request.form.to_dict()

    # --- 核心检测逻辑 ---
    is_attack, attack_info = detector.scan_request(query_params, form_data)

    if is_attack:
        log_msg = f"[!] 拦截攻击！参数：{attack_info['parameter']}, 规则：{attack_info['rule_matched']}, Payload: {attack_info['payload']}"
        print(log_msg)

        with open("waf_alerts.log", "a", encoding="utf-8") as f:
            f.write(log_msg + "\n")

        return jsonify({
            "status": "Blocked",
            "message": "File Inclusion Attack Detected!",
            "rule": attack_info['rule_matched']
        }), 403

    # 转发请求给靶场
    try:
        if request.method == 'GET':
            resp = requests.get(url, params=query_params, headers=request.headers)
        elif request.method == 'POST':
            resp = requests.post(url, data=form_data, headers=request.headers)
        else:
            resp = requests.request(request.method, url, data=request.get_data(), headers=request.headers)
        
        # 过滤掉可能会引起响应冲突的头部
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for (name, value) in resp.raw.headers.items() if name.lower() not in excluded_headers]
        
        return Response(resp.content, resp.status_code, headers)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/waf_logs')
def show_logs():
    try:
        with open("waf_alerts.log", "r", encoding="utf-8") as f:
            logs = f.readlines()
        html = "<h1>WAF 拦截日志</h1><ul>"
        for log in logs:
            html += f"<li>{log}</li>"
        html += "</ul>"
        return html
    except FileNotFoundError:
        return "暂无拦截日志"

if __name__ == '__main__':
    print("[*] WAF 正在启动，监听端口 5000...")
    print("[*] 请访问 http://127.0.0.1:5000 来测试（不要直接访问 8080）")
    app.run(host='0.0.0.0', port=5000, debug=True)