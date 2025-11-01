import socket
import requests
import json
import os
import configparser
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from threading import Thread


class CampusNetworkLogin:
    def __init__(self, root):
        # 设置中文字体支持
        self.root = root
        self.root.title("校园网登录工具")
        self.root.geometry("600x500")
        self.root.resizable(False, False)

        # 确保配置文件存在
        self.config_file = "login_config.ini"
        self.create_config_if_not_exists()

        # 登录状态变量
        self.logged_in = False
        self.auto_login_attempted = False

        # 创建UI
        self.create_widgets()

        # 加载保存的数据
        self.load_saved_data()

        # 检查是否需要自动登录
        self.check_auto_login()

    def create_config_if_not_exists(self):
        """创建配置文件（如果不存在）"""
        if not os.path.exists(self.config_file):
            config = configparser.ConfigParser()
            config['USER_INFO'] = {
                'student_number': '',
                'password': '',
                'isp': '中国联通',
                'auto_login': 'False',
                'last_success': 'False'
            }
            with open(self.config_file, 'w', encoding='utf-8') as f:
                config.write(f)

    def create_widgets(self):
        """创建GUI组件"""
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 账号密码区域
        input_frame = ttk.LabelFrame(main_frame, text="登录信息", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))

        # 学号
        ttk.Label(input_frame, text="学号:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.student_entry = ttk.Entry(input_frame, width=40)
        self.student_entry.grid(row=0, column=1, sticky=tk.W, pady=5)

        # 密码
        ttk.Label(input_frame, text="密码:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.password_entry = ttk.Entry(input_frame, width=40, show="*")
        self.password_entry.grid(row=1, column=1, sticky=tk.W, pady=5)

        # 运营商选择
        ttk.Label(input_frame, text="运营商:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.isp_var = tk.StringVar(value="中国联通")
        isp_combo = ttk.Combobox(
            input_frame,
            textvariable=self.isp_var,
            values=["中国联通", "中国移动", "中国电信"],
            state="readonly",
            width=37
        )
        isp_combo.grid(row=2, column=1, sticky=tk.W, pady=5)

        # 自动登录选项
        self.auto_login_var = tk.BooleanVar(value=False)
        auto_login_check = ttk.Checkbutton(
            input_frame,
            text="自动登录（仅当上次登录成功时）",
            variable=self.auto_login_var
        )
        auto_login_check.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)

        # 按钮区域
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))

        self.login_button = ttk.Button(button_frame, text="登录", command=self.start_login)
        self.login_button.pack(side=tk.LEFT, padx=(0, 10))

        self.logout_button = ttk.Button(button_frame, text="注销", command=self.logout, state=tk.DISABLED)
        self.logout_button.pack(side=tk.LEFT)

        # 日志区域
        log_frame = ttk.LabelFrame(main_frame, text="日志信息", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def load_saved_data(self):
        """加载保存的用户信息"""
        config = configparser.ConfigParser()
        config.read(self.config_file, encoding='utf-8')

        if 'USER_INFO' in config:
            self.student_entry.insert(0, config['USER_INFO'].get('student_number', ''))
            self.password_entry.insert(0, config['USER_INFO'].get('password', ''))
            self.isp_var.set(config['USER_INFO'].get('isp', '中国联通'))
            self.auto_login_var.set(config['USER_INFO'].getboolean('auto_login', False))
            self.last_success = config['USER_INFO'].getboolean('last_success', False)

            self.log("已加载保存的登录信息")

    def save_data(self):
        """保存用户信息到配置文件"""
        config = configparser.ConfigParser()
        config.read(self.config_file, encoding='utf-8')

        if 'USER_INFO' not in config:
            config['USER_INFO'] = {}

        config['USER_INFO']['student_number'] = self.student_entry.get()
        config['USER_INFO']['password'] = self.password_entry.get()
        config['USER_INFO']['isp'] = self.isp_var.get()
        config['USER_INFO']['auto_login'] = str(self.auto_login_var.get())
        config['USER_INFO']['last_success'] = str(self.logged_in)

        with open(self.config_file, 'w', encoding='utf-8') as f:
            config.write(f)

        self.log("已保存登录信息")

    def check_auto_login(self):
        """检查是否需要自动登录"""
        if self.auto_login_var.get() and self.last_success:
            self.log("检测到自动登录设置，尝试自动登录...")
            self.auto_login_attempted = True
            self.start_login()

    def log(self, message):
        """在日志区域显示信息"""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.status_var.set(message)

    def start_login(self):
        """启动登录线程"""
        # 禁用登录按钮防止重复点击
        self.login_button.config(state=tk.DISABLED)
        self.log("准备登录...")

        # 在新线程中执行登录，避免UI冻结
        Thread(target=self.login, daemon=True).start()

    def login(self):
        """执行登录操作"""
        student_number = self.student_entry.get().strip()
        password = self.password_entry.get().strip()
        isp_name = self.isp_var.get()

        # 验证输入
        if not student_number or not password:
            self.log("错误：学号和密码不能为空")
            self.root.after(0, lambda: messagebox.showerror("输入错误", "学号和密码不能为空"))
            self.root.after(0, lambda: self.login_button.config(state=tk.NORMAL))
            return

        # 保存数据
        self.root.after(0, self.save_data)

        # 获取IP地址
        self.log("正在获取内网IP地址...")
        ip_address = self.get_internal_ip()

        if not ip_address:
            self.log("获取IP地址失败，无法登录")
            self.root.after(0, lambda: messagebox.showerror("IP获取失败", "无法获取10.x.x.x网段的内网IP地址"))
            self.root.after(0, lambda: self.login_button.config(state=tk.NORMAL))
            return

        self.log(f"获取到内网IP: {ip_address}")

        # 获取运营商代码
        isp_code = self.get_isp_code(isp_name)
        self.log(f"使用运营商: {isp_name}({isp_code})")

        # 执行登录请求
        self.log("正在发送登录请求...")
        success, msg = self.login_campus_network(student_number, password, isp_code, ip_address)

        # 更新登录状态
        self.logged_in = success

        # 更新UI
        self.root.after(0, lambda: self.update_login_status(success, msg))

    def update_login_status(self, success, msg):
        """更新登录状态UI"""
        if success:
            self.log(f"登录成功: {msg}")
            messagebox.showinfo("登录成功", msg)
            self.login_button.config(state=tk.DISABLED)
            self.logout_button.config(state=tk.NORMAL)
        else:
            self.log(f"登录失败: {msg}")
            messagebox.showerror("登录失败", msg)
            self.login_button.config(state=tk.NORMAL)

        # 保存最终状态
        self.save_data()

    def logout(self):
        """执行注销操作"""
        # 实际应用中需要根据校园网API实现注销功能
        self.log("正在执行注销...")

        # 简单模拟注销过程
        Thread(target=self.simulate_logout, daemon=True).start()

    def simulate_logout(self):
        """模拟注销过程（实际应用中需要替换为真实的注销API调用）"""
        time.sleep(1)  # 模拟网络请求延迟
        self.logged_in = False

        self.root.after(0, lambda: self.update_logout_status())

    def update_logout_status(self):
        """更新注销状态UI"""
        self.log("已注销")
        messagebox.showinfo("注销成功", "已成功注销校园网连接")
        self.login_button.config(state=tk.NORMAL)
        self.logout_button.config(state=tk.DISABLED)
        self.save_data()

    def get_internal_ip(self):
        """获取10.x.x.x网段的内网IP地址"""
        try:
            hostname = socket.gethostname()
            addr_info_list = socket.getaddrinfo(hostname, None)

            for info in addr_info_list:
                if len(info) >= 5 and isinstance(info[4], tuple) and info[4]:
                    ip_address = info[4][0]
                    if ip_address.startswith("10."):
                        return ip_address

            return None

        except Exception as e:
            self.log(f"获取IP地址时出错: {str(e)}")
            return None

    def get_isp_code(self, isp_name):
        """根据运营商名称获取对应的代码"""
        isp_mapping = {
            "中国联通": "cucc",
            "中国移动": "cmcc",
            "中国电信": "ctcc"
        }
        return isp_mapping.get(isp_name, "")

    def extract_msg_from_response(self, response_text):
        """从响应中提取msg字段"""
        try:
            # 处理JSONP格式和可能的分号
            clean_text = response_text.strip().rstrip(';')

            if clean_text.startswith('dr1003(') and clean_text.endswith(')'):
                json_str = clean_text[len('dr1003('):-1]
            else:
                json_str = clean_text

            data = json.loads(json_str)
            return data.get('msg', '未获取到提示信息')

        except json.JSONDecodeError:
            return f"响应格式错误: {clean_text[:100]}"
        except Exception as e:
            return f"解析响应出错: {str(e)}"

    def login_campus_network(self, student_number, password, isp, ip_address):
        """发送登录请求到校园网服务器"""
        try:
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

            response = requests.get(login_url, timeout=(5, 10))
            response.encoding = 'utf-8'

            msg = self.extract_msg_from_response(response.text)
            return "成功" in msg, msg

        except requests.exceptions.ConnectTimeout:
            return False, "网络连接超时，请检查校园网是否可用"
        except requests.exceptions.ReadTimeout:
            return False, "读取响应超时，请稍后重试"
        except requests.exceptions.RequestException as e:
            return False, f"网络请求出错: {str(e)}"
        except Exception as e:
            return False, f"登录过程出错: {str(e)}"


if __name__ == "__main__":
    root = tk.Tk()
    app = CampusNetworkLogin(root)
    root.mainloop()
