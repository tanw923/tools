from ..app import json,requests,request,make_response,socket,jsonify,Blueprint,plugins
import base64
api = Blueprint('api', __name__)


def getjson():
    return json.loads(request.get_data().decode("utf-8"))


# 信息泄露
@api.route('/information', methods=['post'])
def information_api():
    information_load = getjson()
    information_url = information_load['url']
    information_type = information_load['type']
    information_poc_result = list(plugins.angelsword['informationpocdict'].values())[information_type](information_url).run()
    if "[+]" in information_poc_result:
        information_poc_status = 1
    else:
        information_poc_status = 0
    return jsonify({"status": information_poc_status, "pocresult": information_poc_result})


# 工控安全
@api.route('/industrial', methods=['post'])
def industrial_api():
    industrial_load = getjson()
    industrial_url = industrial_load['url']
    industrial_type = industrial_load['type']
    industrial_poc_result = list(plugins.angelsword['industrialpocdict'].values())[industrial_type](industrial_url).run()
    if "[+]" in industrial_poc_result:
        industrial_poc_status = 1
    else:
        industrial_poc_status = 0
    return jsonify({"status": industrial_poc_status, "pocresult": industrial_poc_result})


# 物联网安全
@api.route('/hardware', methods=['post'])
def hardware_api():
    hardware_load = getjson()
    hardware_url = hardware_load['url']
    hardware_type = hardware_load['type']
    hardware_poc_result = list(plugins.angelsword['hardwarepocdict'].values())[hardware_type](hardware_url).run()
    if "[+]" in hardware_poc_result:
        hardware_poc_status = 1
    else:
        hardware_poc_status = 0
    return jsonify({"status": hardware_poc_status, "pocresult": hardware_poc_result})


# system安全
@api.route('/system', methods=['post'])
def system_api():
    system_load = getjson()
    system_url = system_load['url']
    system_type = system_load['type']
    system_poc_result = list(plugins.angelsword['systempocdict'].values())[system_type](system_url).run()
    if "[+]" in system_poc_result:
        system_poc_status = 1
    else:
        system_poc_status = 0
    return jsonify({"status": system_poc_status, "pocresult": system_poc_result})


# cms漏洞利用
@api.route('/cms', methods=['post'])
def cms_api():
    cmsexp_load = getjson()
    cmsexp_url = cmsexp_load['url']
    cmsexp_type = cmsexp_load['type']
    cmsexp_poc_result = list(plugins.angelsword['cmspocdict'].values())[cmsexp_type](cmsexp_url).run()
    if cmsexp_poc_result is not None:
        if "[+]" in cmsexp_poc_result:
            cmsexp_poc_status = 1
        else:
            cmsexp_poc_status = 0
    else:
        cmsexp_poc_result = "[-]no vuln"
        cmsexp_poc_status = 0
    return jsonify({"status": cmsexp_poc_status, "pocresult": cmsexp_poc_result})


# 简单的子域名收集
@api.route('/subdomain', methods=['post'])
def subdomain_api():
    domain_json = getjson()
    return requests.get("http://ce.baidu.com/index/getRelatedSites?site_address={domain}".format(domain=domain_json['domain'])).text

# 简单的base64加密解密
@api.route('/baseflag', methods=['post'])
def baseflag_api():
    base_json = getjson()
    return jsonify({'data': str(base64.b64encode({code}.encode("utf-8")), "utf-8").text})


# 简单的nmap扫描
@api.route('/nmap', methods=['post'])
def nmap_api():
    target_json = getjson()
    return jsonify({'data': requests.get("https://api.hackertarget.com/nmap/?q={target}".format(target=target_json['target'].replace("http:", "").replace("https:", "").replace("/", ""))).text})

