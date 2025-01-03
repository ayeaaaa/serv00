import os
import subprocess
import socket
import time
import requests
import paramiko
import threading
import tkinter as tk
from tkinter import scrolledtext
import re  # 导入正则表达式模块

# 远程执行命令的函数
def run_remote_command_with_paramiko(host, ssh_user, ssh_pass, tcp_port, udp1_port, udp2_port, nezha_server, nezha_port, nezha_key, argo_domain, argo_auth, cfip, cfport, use_nezha, use_tunnel):
    # 如果选择了使用 Nezha，则设置相关变量
    nezha_env = ""
    if use_nezha:
        nezha_env = f"NEZHA_SERVER={nezha_server} NEZHA_PORT={nezha_port} NEZHA_KEY={nezha_key}"
    
    # 如果选择了使用固定隧道，则设置相关变量
    tunnel_env = ""
    if use_tunnel:
        tunnel_env = f"ARGO_DOMAIN={argo_domain} ARGO_AUTH='{argo_auth}' "
        
    # 构建远程命令
    remote_command = f"""{tunnel_env}VMESS_PORT={tcp_port} HY2_PORT={udp1_port} TUIC_PORT={udp2_port} {nezha_env} CFIP={cfip} CFPORT={cfport} bash <(curl -Ls https://raw.githubusercontent.com/eooce/sing-box/main/sb_00.sh)"""
    print(f"构建的命令: {remote_command}")
    try:
        # 创建 SSH 客户端对象
        ssh_client = paramiko.SSHClient()
        # 自动添加主机密钥（如果没有密钥的话）
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # 连接到远程主机
        ssh_client.connect(host, username=ssh_user, password=ssh_pass)
        # 执行远程命令
        stdin, stdout, stderr = ssh_client.exec_command(remote_command)

        # 实时回显输出
        output = ""
        while True:
            line = stdout.channel.recv(1024).decode('utf-8')
            if not line:
                break
            output += line + "\n"
            # 去除转义字符
            line = remove_escape_sequences(line)
            # 根据输出内容选择颜色
            if "error" in line.lower():
                append_output(line, "red")
            elif "success" in line.lower():
                append_output(line, "green")
            else:
                append_output(line, "blue")

        # 错误输出
        error = stderr.read().decode('utf-8')
        if error:
            append_output(f"错误输出:\n{remove_escape_sequences(error)}\n", "red")

        # 关闭 SSH 客户端连接
        ssh_client.close()
        return output
    except Exception as e:
        append_output(f"执行命令失败: {e}\n", "red")
        return f"连接或命令执行失败: {e}"

# 去除转义字符的函数
def remove_escape_sequences(text):
    # 使用正则表达式去除转义字符
    return re.sub(r'\x1b\[[0-9;]*[mGKHMS]','', text)

# 向界面添加输出并设置颜色
def append_output(text, color):
    output_text.insert(tk.END, text)
    if color == "red":
        output_text.tag_add("error", "1.0", tk.END)
        output_text.tag_configure("error", foreground="red")
    elif color == "green":
        output_text.tag_add("success", "1.0", tk.END)
        output_text.tag_configure("success", foreground="green")
    else:
        output_text.tag_add("info", "1.0", tk.END)
        output_text.tag_configure("info", foreground="blue")
    output_text.yview(tk.END)  # 滚动到最新行

# 处理提交按钮的操作
def submit():
    # 获取用户输入的各个配置
    host = host_entry.get()
    ssh_user = ssh_user_entry.get()
    ssh_pass = ssh_pass_entry.get()
    tcp_port = int(tcp_port_entry.get())
    udp1_port = int(udp1_port_entry.get())
    udp2_port = int(udp2_port_entry.get())
    nezha_server = nezha_server_entry.get()
    nezha_port = nezha_port_entry.get()
    nezha_key = nezha_key_entry.get()
    argo_domain = argo_domain_entry.get()
    argo_auth = argo_auth_entry.get()
    cfip = cfip_entry.get()
    cfport = int(cfport_entry.get())

    # 获取复选框状态
    use_nezha = use_nezha_var.get()
    use_tunnel = use_tunnel_var.get()

    # 创建服务器配置字典
    servers = {
        host: (ssh_user, ssh_pass, tcp_port, udp1_port, udp2_port, nezha_server, nezha_port, nezha_key, argo_domain, argo_auth, use_nezha, use_tunnel)
    }

    # 清空 Text 控件
    output_text.delete(1.0, tk.END)

    # 在后台线程中执行远程操作，避免阻塞 UI 线程
    threading.Thread(target=execute_remote_command, args=(servers, cfip, cfport)).start()

# 在后台执行远程命令
def execute_remote_command(servers, cfip, cfport):
    for host, config in servers.items():
        ssh_user, ssh_pass, tcp_port, udp1_port, udp2_port, nezha_server, nezha_port, nezha_key, argo_domain, argo_auth, use_nezha, use_tunnel = config
        try:
            append_output(f"开始一键四协议架设 vmess-ws|vmess-ws-tls(argo)|hysteria2|tuic: \n 主机: {host}\n", "info")
            append_output(f"本程序所用脚本来自于 Serv00|ct8老王 sing-box 一键四协议安装脚本\n", "info")
            append_output(f"正在 ssh 连接 {host}，稍安勿躁\n", "info")
            append_output(f"以下为 SSH 回显内容\n", "info")
            append_output(f"============================================================\n\n", "info")
            result = run_remote_command_with_paramiko(
                host, ssh_user, ssh_pass, tcp_port, udp1_port, udp2_port, nezha_server, nezha_port, nezha_key, argo_domain, argo_auth, cfip, cfport, use_nezha, use_tunnel
            )
            append_output(f"============================================================\n\n上面如果显示出节点信息说明架设成功", "green")
        except Exception as e:
            append_output(f"\n")

# 创建 Tkinter GUI
def create_gui():
    global host_entry, ssh_user_entry, ssh_pass_entry, tcp_port_entry, udp1_port_entry, udp2_port_entry
    global nezha_server_entry, nezha_port_entry, nezha_key_entry, argo_domain_entry, argo_auth_entry, cfip_entry, cfport_entry, output_text
    global use_nezha_var, use_tunnel_var

    root = tk.Tk()
    root.title("SERV00一键四协议架设 v241224 by ayeaaaa")

    # 设置窗口大小
    root.geometry("900x550")

    # 创建框架
    main_frame = tk.Frame(root)
    main_frame.pack(fill=tk.BOTH, expand=True)

    # 创建左侧框架（配置部分）
    config_frame = tk.Frame(main_frame, padx=10, pady=10)
    config_frame.grid(row=0, column=0, sticky="nsew")

    # 创建右侧框架（回显部分）
    output_frame = tk.Frame(main_frame, padx=10, pady=10)
    output_frame.grid(row=0, column=1, sticky="nsew")

    # 输入框标签
    labels = [
        "Host:", "SSH 用户名:", "SSH 密码:", "TCP 端口:", "UDP1 端口:", "UDP2 端口:", "Nezha 服务器:", 
        "Nezha 端口:", "Nezha Key:", "Argo 域名:", "Argo Auth:", "优选 IP:", "优选 端口:"
    ]
    
    for i, label in enumerate(labels):
        tk.Label(config_frame, text=label, font=("Arial", 12)).grid(row=i, column=0, sticky="w", pady=5)

    # 输入框
    host_entry = tk.Entry(config_frame, font=("Arial", 12))
    ssh_user_entry = tk.Entry(config_frame, font=("Arial", 12))
    ssh_pass_entry = tk.Entry(config_frame, font=("Arial", 12))
    tcp_port_entry = tk.Entry(config_frame, font=("Arial", 12))
    udp1_port_entry = tk.Entry(config_frame, font=("Arial", 12))
    udp2_port_entry = tk.Entry(config_frame, font=("Arial", 12))

    # 修改下面这几行：设置它们的背景颜色为灰色，并设置为不可编辑
    nezha_server_entry = tk.Entry(config_frame, font=("Arial", 12), state="disabled", bg="gray")
    nezha_port_entry = tk.Entry(config_frame, font=("Arial", 12), state="disabled", bg="gray")
    nezha_key_entry = tk.Entry(config_frame, font=("Arial", 12), state="disabled", bg="gray")
    argo_domain_entry = tk.Entry(config_frame, font=("Arial", 12), state="disabled", bg="gray")
    argo_auth_entry = tk.Entry(config_frame, font=("Arial", 12), state="disabled", bg="gray")
    cfip_entry = tk.Entry(config_frame, font=("Arial", 12))
    cfport_entry = tk.Entry(config_frame, font=("Arial", 12))

    # 设置输入框位置
    entries = [
        host_entry, ssh_user_entry, ssh_pass_entry, tcp_port_entry, udp1_port_entry, udp2_port_entry,
        nezha_server_entry, nezha_port_entry, nezha_key_entry, argo_domain_entry, argo_auth_entry, cfip_entry, cfport_entry
    ]
    
    for i, entry in enumerate(entries):
        entry.grid(row=i, column=1, pady=5)

    # 创建复选框变量
    use_nezha_var = tk.BooleanVar()
    use_tunnel_var = tk.BooleanVar()

    # 在配置框架中添加复选框
    use_nezha_checkbox = tk.Checkbutton(config_frame, text="使用 Nezha", variable=use_nezha_var, font=("Arial", 12), command=toggle_nezha_inputs)
    use_nezha_checkbox.grid(row=len(labels), column=0, sticky="w", pady=5)

    use_tunnel_checkbox = tk.Checkbutton(config_frame, text="使用固定隧道", variable=use_tunnel_var, font=("Arial", 12), command=toggle_argo_inputs)
    use_tunnel_checkbox.grid(row=len(labels), column=1, sticky="w", pady=5)

    # 创建提交按钮
    submit_button = tk.Button(config_frame, text="开始架设代理", font=("Arial", 12), command=submit)
    submit_button.grid(row=len(labels)+1, column=0, columnspan=2, pady=10)

    # 创建输出区域
    output_text = scrolledtext.ScrolledText(output_frame, width=60, height=20, font=("Arial", 12))
    output_text.pack(fill=tk.BOTH, expand=True)

    # 启动 GUI
    root.mainloop()

# 切换 Nezha 输入框的可用状态
def toggle_nezha_inputs():
    if use_nezha_var.get():
        nezha_server_entry.config(state="normal", bg="white")
        nezha_port_entry.config(state="normal", bg="white")
        nezha_key_entry.config(state="normal", bg="white")
    else:
        nezha_server_entry.config(state="disabled", bg="gray")
        nezha_port_entry.config(state="disabled", bg="gray")
        nezha_key_entry.config(state="disabled", bg="gray")
        nezha_server_entry.delete(0, tk.END)
        nezha_port_entry.delete(0, tk.END)
        nezha_key_entry.delete(0, tk.END)
		

def toggle_argo_inputs():
    if use_tunnel_var.get():
        argo_domain_entry.config(state="normal", bg="white")
        argo_auth_entry.config(state="normal", bg="white")
    else:
        argo_domain_entry.config(state="disabled", bg="gray")
        argo_auth_entry.config(state="disabled", bg="gray")

# 启动 GUI 应用
create_gui()
