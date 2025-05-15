from flask import Flask, request, jsonify
import json
import threading
import os
app = Flask(__name__)
DATA_FILE = "community_rules.json"
SCORE_FILE = "community_scores.json"
USER_FILE = "community_users.json"
TAG_FILE = "community_tags.json"
REPORT_FILE = "community_reports.json"
lock = threading.Lock()
def load_rules():
    if not os.path.exists(DATA_FILE):
        return []
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return []
def save_rules(rules):
    #保存rule
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(rules, f, ensure_ascii=False, indent=2)
def load_scores():
    #加载用户评分
    if not os.path.exists(SCORE_FILE):
        return {}
    with open(SCORE_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}
def save_scores(scores):
    with open(SCORE_FILE, "w", encoding="utf-8") as f:
        json.dump(scores, f, ensure_ascii=False, indent=2)
def load_users():
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}
def save_users(users):
    with open(USER_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)
def load_tags():
    #加载label
    if not os.path.exists(TAG_FILE):
        return {}
    with open(TAG_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return {}
def save_tags(tags):
    # 保存label
    with open(TAG_FILE, "w", encoding="utf-8") as f:
        json.dump(tags, f, ensure_ascii=False, indent=2)
def load_reports():
    #加载举报
    if not os.path.exists(REPORT_FILE):
        return []
    with open(REPORT_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return []
def save_reports(reports):
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(reports, f, ensure_ascii=False, indent=2)
@app.route("/register", methods=["POST"])
def register():
    #注册
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400
    with lock:
        users = load_users()
        if username in users:
            return jsonify({"error": "用户名已存在"}), 409
        users[username] = {"password": password}
        save_users(users)
    return jsonify({"msg": "注册成功"})
@app.route("/login", methods=["POST"])
def login():
    #登录
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "用户名和密码不能为空"}), 400
    users = load_users()
    if username not in users or users[username]["password"] != password:
        return jsonify({"error": "用户名或密码错误"}), 401
    return jsonify({"msg": "登录成功"})
@app.route("/change_password", methods=["POST"])
def change_password():
    #用户更改自己的登录密码
    data = request.get_json()
    username = data.get("username")
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    if not username or not old_password or not new_password:
        return jsonify({"error": "参数不能为空"}), 400
    with lock:
        users = load_users()
        if username not in users or users[username]["password"] != old_password:
            return jsonify({"error": "用户名或原密码错误"}), 401
        users[username]["password"] = new_password
        save_users(users)
    return jsonify({"msg": "密码修改成功"})
@app.route("/rules", methods=["GET"])
def get_rules():
    # 加载规则列表
    rules = load_rules()
    scores = load_scores()
    tags = load_tags()
    # 支持标签筛选和搜索
    tag_filter = request.args.get("tag", "").strip()
    search = request.args.get("search", "").strip().lower()
    rule_list = []
    for i, r in enumerate(rules):
        score_info = scores.get(str(i), {})
        if isinstance(score_info, dict):
            score_count = len(score_info)
            avg_score = round(sum(score_info.values())/score_count, 2) if score_count > 0 else 0
        elif isinstance(score_info, list):
            score_count = len(score_info)
            avg_score = round(sum(score_info)/score_count, 2) if score_count > 0 else 0
        else:
            score_count = 0
            avg_score = 0
        rule_tags = tags.get(str(i), [])
        # 标签筛选
        if tag_filter and tag_filter not in rule_tags:
            continue
        # 搜索（规则名、简介、标签、作者）
        if search:
            if (search not in r.get("name", "").lower() and
                search not in r.get("desc", "").lower() and
                search not in r.get("username", "").lower() and
                not any(search in t.lower() for t in rule_tags)):
                continue
        rule_list.append({
            "id": i,
            "name": r.get("name", ""),
            "desc": r.get("desc", ""),
            "username": r.get("username", ""),
            "score_count": score_count,
            "avg_score": avg_score,
            "tags": rule_tags
        })
    rule_list.sort(key=lambda x: x["avg_score"], reverse=True)
    return jsonify({
        "server_ip": "116.62.80.32",
        "rules": rule_list
    })
@app.route("/rule/<int:rule_id>", methods=["GET"])
def get_rule(rule_id):
    rules = load_rules()
    tags = load_tags()
    if 0 <= rule_id < len(rules):
        rule = rules[rule_id]
        return jsonify({
            "username": rule.get("username", ""),
            "name": rule.get("name", ""),
            "desc": rule.get("desc", ""),
            "rules": rule.get("rules", []),
            "tags": tags.get(str(rule_id), [])
        })
    return jsonify({"error": "not found"}), 404
@app.route("/upload", methods=["POST"])
def upload_rule():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    rule_name = data.get("name", "")
    tags = data.get("tags", [])
    if not data or not username or not password or not rule_name or "rules" not in data:
        return jsonify({"error": "invalid data"}), 400
    with lock:
        users = load_users()
        if username not in users or users[username]["password"] != password:
            return jsonify({"error": "用户未登录或密码错误"}), 401
        rules = load_rules()
        for r in rules:
            if r.get("username") == username and r.get("name") == rule_name:
                return jsonify({"error": "同一用户下规则名称已存在"}), 409
        rules.append({
            "username": username,
            "name": rule_name,
            "desc": data.get("desc", ""),
            "rules": data.get("rules", [])
        })
        save_rules(rules)
        # 保存标签
        tags_map = load_tags()
        tags_map[str(len(rules)-1)] = tags if isinstance(tags, list) else []
        save_tags(tags_map)
    return jsonify({"msg": "ok"})
@app.route("/set_tags", methods=["POST"])
def set_tags():
    data = request.get_json()
    rule_id = str(data.get("rule_id"))
    username = data.get("username")
    tags = data.get("tags", [])
    rules = load_rules()
    if not rule_id or not username or not isinstance(tags, list):
        return jsonify({"error": "invalid data"}), 400
    rule_id_int = int(rule_id)
    if not (0 <= rule_id_int < len(rules)):
        return jsonify({"error": "rule not found"}), 404
    if rules[rule_id_int].get("username") != username:
        return jsonify({"error": "只能修改自己上传的规则标签"}), 403
    with lock:
        tags_map = load_tags()
        tags_map[rule_id] = tags
        save_tags(tags_map)
    return jsonify({"msg": "ok"})
@app.route("/report", methods=["POST"])
def report_rule():
    data = request.get_json()
    rule_id = str(data.get("rule_id"))
    username = data.get("username", "")
    reason = data.get("reason", "")
    if not rule_id or not reason:
        return jsonify({"error": "invalid data"}), 400
    with lock:
        reports = load_reports()
        reports.append({
            "rule_id": rule_id,
            "username": username,
            "reason": reason
        })
        save_reports(reports)
    return jsonify({"msg": "举报成功"})
@app.route("/rate", methods=["POST"])
def rate_rule():
    data = request.get_json()
    rule_id = str(data.get("rule_id"))
    score = int(data.get("score", 0))
    username = data.get("username", None)
    if not rule_id or not (1 <= score <= 5) or not username:
        return jsonify({"error": "invalid data"}), 400
    with lock:
        scores = load_scores()
        if rule_id not in scores:
            scores[rule_id] = {}
        # 只保留每个用户最后一次评分
        scores[rule_id][username] = score
        save_scores(scores)
    return jsonify({"msg": "ok"})
@app.route("/delete_rule", methods=["POST"])
def delete_rule():
    data = request.get_json()
    rule_id = data.get("rule_id")
    username = data.get("username")
    if rule_id is None or username is None:
        return jsonify({"error": "参数不完整"}), 400
    with lock:
        rules = load_rules()
        try:
            rule_id_int = int(rule_id)
        except Exception:
            return jsonify({"error": "rule_id格式错误"}), 400
        if not (0 <= rule_id_int < len(rules)):
            return jsonify({"error": "规则不存在"}), 404
        if rules[rule_id_int].get("username") != username:
            return jsonify({"error": "只能删除自己上传的规则"}), 403
        # 删除规则
        del rules[rule_id_int]
        save_rules(rules)
        tags = load_tags()
        scores = load_scores()
        reports = load_reports()
        tags.pop(str(rule_id), None)
        scores.pop(str(rule_id), None)
        reports = [r for r in reports if r.get("rule_id") != str(rule_id)]
        def reindex_dict(d):
            return {str(i): d.get(str(old_i), []) for i, old_i in enumerate(sorted(map(int, d.keys()))) if str(old_i) in d}
        tags_new = {}
        scores_new = {}
        for i, rule in enumerate(rules):
            tags_new[str(i)] = tags.get(str(i), [])
            scores_new[str(i)] = scores.get(str(i), {})
        save_tags(tags_new)
        save_scores(scores_new)
        save_reports(reports)
    return jsonify({"msg": "删除成功"})
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80, debug=False)