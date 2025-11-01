import socket
import requests
import json


def get_internal_ip():
    """获取10.x.x.x网段的内网IP地址"""
    try:
        hostname = socket.gethostname()
        addr_info_list = socket.getaddrinfo(hostname, None)

        for info in addr_info_list:
            if len(info) >= 5 and isinstance(info[4], tuple) and info[4]:
                ip_address = info[4][0]
                if ip_address.startswith("10."):
                    return ip_address

        print("未找到10.x.x.x网段的内网IP地址")
        return None

    except Exception as e:
        print(f"获取IP地址时出错: {str(e)}")
        return None


def get_isp_code(isp_name):
    """根据运营商名称获取对应的代码"""
    isp_mapping = {
        "中国联通": "cucc",
        "中国移动": "cmcc",
        "中国电信": "cmc"
    }
    return isp_mapping.get(isp_name, "")


def extract_msg_from_response(response_text):
    try:
        # 1. 移除响应末尾可能的分号（解决当前报错的核心问题）
        clean_text = response_text.strip().rstrip(';')

        # 2. 处理JSONP格式：去掉开头的"dr1003("和结尾的")"
        if clean_text.startswith('dr1003(') and clean_text.endswith(')'):
            json_str = clean_text[len('dr1003('):-1]
        else:
            json_str = clean_text

        # 3. 解析JSON并提取msg字段
        data = json.loads(json_str)
        # 同时返回result/ret_code辅助判断状态，msg字段优先显示
        result = data.get('result', '未知结果码')
        ret_code = data.get('ret_code', '未知返回码')
        msg = data.get('msg', '响应中未包含msg字段')

        return f"状态码: result={result}, ret_code={ret_code} | 提示信息: {msg}"

    except json.JSONDecodeError:
        return f"JSON解析失败，原始响应（前150字符）: {clean_text[:150]}"
    except Exception as e:
        return f"提取msg字段出错: {str(e)}"


def login_campus_network(student_number, password, isp, ip_address):
    """登录校园网并返回带msg字段的结果"""
    if not all([student_number, password, isp, ip_address]):
        return False, "登录信息不完整（学号/密码/运营商/IP缺一不可）"

    try:
        # 构建登录URL（保留原参数结构，确保与校园网接口匹配）
        login_url = (
            f'http://172.22.5.2:801/eportal/portal/login'
            f'?callback=dr1003&login_method=1'
            f'&user_account=%2C0%2C{student_number}%40{isp}'
            f'&user_password={password}'
            f'&wlan_user_ip={ip_address}'
            f'&wlan_user_ipv6=&wlan_user_mac=000000000000'
            f'&wlan_ac_ip=&wlan_ac_name=&jsVersion=4.2'
            f'&terminal_type=3&lang=zh-cn&v=906&lang=zh'
        )

        # 发送请求（添加连接超时和读取超时，避免卡住）
        response = requests.get(login_url, timeout=(5, 10))
        response.encoding = 'utf-8'  # 强制UTF-8解码，避免中文乱码

        # 提取并返回msg相关信息
        msg_info = extract_msg_from_response(response.text)
        # 根据msg判断登录是否成功（包含"成功"关键词则视为成功）
        is_success = "成功" in msg_info

        return is_success, msg_info

    except requests.exceptions.ConnectTimeout:
        return False, "网络连接超时（可能是校园网网关不可达）"
    except requests.exceptions.ReadTimeout:
        return False, "读取响应超时（可能是接口负载过高）"
    except requests.exceptions.RequestException as e:
        return False, f"网络请求出错: {str(e)}"
    except Exception as e:
        return False, f"登录过程异常: {str(e)}"


if __name__ == "__main__":
    # 配置登录信息（可根据实际情况修改）
    student_number = "24330474130z"
    password = "123456"
    isp_name = "中国联通"

    # 流程化执行登录
    print("=" * 50)
    print("校园网登录工具")
    print("=" * 50)

    print("\n1. 正在获取内网IP地址...")
    ip_address = get_internal_ip()
    if not ip_address:
        print("获取IP失败，程序中止")
        exit()

    print(f"2. 正在匹配运营商代码...")
    isp_code = get_isp_code(isp_name)
    if not isp_code:
        print(f"不支持的运营商: {isp_name}（仅支持联通/移动/电信）")
        exit()

    print(f"\n登录参数确认:")
    print(f"- 学号: {student_number}")
    print(f"- 运营商: {isp_name}（代码: {isp_code}）")
    print(f"- 内网IP: {ip_address}")
    print("\n3. 正在发送登录请求...")

    # 执行登录并打印结果
    success, result_msg = login_campus_network(student_number, password, isp_code, ip_address)
    print(f"\n登录结果:")
    print(f"- 登录状态: {'成功' if success else '失败'}")
    print(f"- 详细信息: {result_msg}")
    print("\n" + "=" * 50)