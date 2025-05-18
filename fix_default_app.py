import winreg
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import ctypes
import sys
import subprocess
import os
import threading
import keyboard  
import json
import hashlib
import time
from collections import Counter
import requests  
import ttkbootstrap as tb 
from PIL import Image  
import shutil
import ctypes
import hashlib
def set_default_app_cmd(file_extension, app_path):
    """
    使用 Windows 命令行工具设置默认打开程序，兼容 Windows 10/11
    """
    try:
        ext = file_extension if file_extension.startswith('.') else '.' + file_extension
        prog_id = ext[1:].upper() + "File"
        subprocess.run(f'assoc {ext}={prog_id}', shell=True, check=True)
        subprocess.run(f'ftype {prog_id}="{app_path}" "%1"', shell=True, check=True)
        return True, ""
    except Exception as e:
        return False, str(e)
def set_default_app(file_extension, app_path, icon_path=None):
    """
    先用命令行设置，再用注册表补充
    """
    ok, msg = set_default_app_cmd(file_extension, app_path)
    if not ok:
        print(f"命令行设置fail: {msg}")
    try:
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, file_extension) as key:
            prog_id = winreg.QueryValue(key, None)
            if not prog_id:
                prog_id = file_extension[1:].upper() + "File"
                winreg.SetValue(key, None, winreg.REG_SZ, prog_id)
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, f"{prog_id}\\shell\\open\\command") as cmd_key:
                winreg.SetValue(cmd_key, None, winreg.REG_SZ, f"\"{app_path}\" \"%1\"")
        user_choice_path = f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\{file_extension}\\"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, user_choice_path, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.DeleteKey(key, "UserChoice")
        except WindowsError:
            pass
        try:
            user_sid = os.getlogin()
        except Exception:
            user_sid = "unknown"
        timestamp = int(time.time())
        hash_input = f"{prog_id}{user_sid}{timestamp}".encode('utf-16le')
        hash_value = hashlib.sha256(hash_input).hexdigest()
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, user_choice_path + "UserChoice") as key:
            winreg.SetValueEx(key, "ProgId", 0, winreg.REG_SZ, prog_id)
            winreg.SetValueEx(key, "Hash", 0, winreg.REG_SZ, hash_value)
        print(f"成功设置 {file_extension} 的默认打开程序为: {app_path}")
    except Exception as e:
        print(f"设置默认程序失败: {e}")
def check_default_app(file_extension, app_path):
    """检查当前扩展名的默认打开程序是否为 app_path
    """
    ext = file_extension if file_extension.startswith('.') else '.' + file_extension
    try:
        output = subprocess.check_output(f"assoc {ext}", shell=True, encoding="gbk", errors="ignore")
        if "=" not in output:
            return False
        prog_id = output.strip().split("=")[-1]
        output2 = subprocess.check_output(f"ftype {prog_id}", shell=True, encoding="gbk", errors="ignore")
        if app_path.lower() in output2.lower():
            return True
    except Exception:
        pass
    return False
# 拖拽式规则编辑器
class RuleEditor(tk.Toplevel):
    def __init__(self, master, rules):
        super().__init__(master)
        self.title("文件关联规则编辑器")
        self.geometry("500x400")
        self.rules = rules  
        self.listbox = tk.Listbox(self, selectmode=tk.SINGLE, width=60)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.refresh_list()
        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)
        tk.Button(btn_frame, text="添加rules", command=self.add_rule).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="编辑rules", command=self.edit_rule).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="删除rules", command=self.delete_rule).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="上移", command=self.move_up).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="下移", command=self.move_down).pack(side=tk.LEFT, padx=5)
        tk.Button(self, text="保存并关闭", command=self.save_and_close).pack(pady=5)
        self.protocol("WM_DELETE_WINDOW", self.save_and_close)
    def refresh_list(self):
        #刷新
        self.listbox.delete(0, tk.END)
        for idx, rule in enumerate(self.rules):
            self.listbox.insert(tk.END, f"{idx+1}. {rule['ext']} → {rule['app']} (优先级:{rule['priority']})")
    def add_rule(self):
        #加规则
        ext = simpledialog.askstring("扩展名", "请输入文件扩展名（如 .txt）", parent=self)
        app = filedialog.askopenfilename(title="选择应用程序")
        if ext and app:
            rule = {'ext': ext, 'app': app, 'priority': len(self.rules)+1}
            self.rules.append(rule)
            self.refresh_list()
    def edit_rule(self):
        #写规则
        idx = self.listbox.curselection()
        if not idx:
            return
        idx = idx[0]
        rule = self.rules[idx]
        ext = simpledialog.askstring("扩展名", "修改扩展名", initialvalue=rule['ext'], parent=self)
        app = filedialog.askopenfilename(title="选择应用程序")
        if ext and app:
            rule = {'ext': ext, 'app': app, 'priority': rule['priority']}
            self.rules[idx] = rule
            self.refresh_list()
    def delete_rule(self):
        idx = self.listbox.curselection()
        if not idx:
            return
        del self.rules[idx[0]]
        for i, r in enumerate(self.rules):
            r['priority'] = i+1
        self.refresh_list()
    def move_up(self):
        idx = self.listbox.curselection()
        if not idx or idx[0] == 0:
            return
        i = idx[0]
        self.rules[i-1], self.rules[i] = self.rules[i], self.rules[i-1]
        self.rules[i-1]['priority'], self.rules[i]['priority'] = i, i+1
        self.refresh_list()
        self.listbox.select_set(i-1)
    def move_down(self):
        idx = self.listbox.curselection()
        if not idx or idx[0] == len(self.rules)-1:
            return
        i = idx[0]
        self.rules[i+1], self.rules[i] = self.rules[i], self.rules[i+1]
        self.rules[i+1]['priority'], self.rules[i]['priority'] = i+2, i+1
        self.refresh_list()
    def save_and_close(self):
        self.destroy()
rules = []
def apply_rules():
    for rule in sorted(rules, key=lambda x: x['priority']):
        set_default_app(rule['ext'], rule['app'])
def export_rules():
    file = filedialog.asksaveasfilename(
        defaultextension=".json",
        filetypes=[("JSON 文件", "*.json")],
        title="导出规则到file"
    )
    if file:
        try:
            with open(file, "w", encoding="utf-8") as f:
                json.dump(rules, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("导出成功", "规则已成功导出！")
        except Exception as e:
            messagebox.showerror("导出失败", f"导出规则失败: {e}")
def import_rules():
    file = filedialog.askopenfilename(
        filetypes=[("JSON 文件", "*.json")],
        title="导入规则文件"
    )
    if file:
        try:
            with open(file, "r", encoding="utf-8") as f:
                imported = json.load(f)
            if isinstance(imported, list):
                rules.clear()
                for r in imported:
                    if 'ext' in r and 'app' in r and 'priority' in r:
                        rules.append(r)
                for i, r in enumerate(rules):
                    r['priority'] = i+1
                apply_rules()
                messagebox.showinfo("导入成功", "规则已成功导入并应用！")
            else:
                messagebox.showerror("导入失败", "文件格式不正确")
        except Exception as e:
            messagebox.showerror("导入失败", f"导入规则失败: {e}")
def show_stats():
    # 获取系统所有扩展名和默认程序
    stats = []
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "") as root:
            i = 0
            while True:
                try:
                    subkey = winreg.EnumKey(root, i)
                    if subkey.startswith("."):
                        ext = subkey
                        try:
                            with winreg.OpenKey(root, ext) as ext_key:
                                progid, _ = winreg.QueryValueEx(ext_key, None)
                                if progid:
                                    try:
                                        with winreg.OpenKey(root, f"{progid}\\shell\\open\\command") as cmd_key:
                                            cmd, _ = winreg.QueryValueEx(cmd_key, None)
                                            stats.append((ext, cmd))
                                    except Exception:
                                        stats.append((ext, "（未找到打开命令）"))
                                else:
                                    stats.append((ext, "（未设置默认程序）"))
                        except Exception:
                            stats.append((ext, "（无法读取）"))
                    i += 1
                except OSError:
                    break
    except Exception as e:
        messagebox.showerror("统计失败", f"读取注册表失败: {e}")
        return
    '''搜索'''
    stat_win = tk.Toplevel()
    stat_win.title("默认程序设定统计")
    stat_win.geometry("800x600")
    stat_win.configure(bg="#f5f6fa")
    tk.Label(stat_win, text="系统扩展名与默认程序对应表", font=("微软雅黑", 15, "bold"), bg="#f5f6fa", fg="#273c75").pack(pady=12, fill="x")
    # 搜索框
    search_var = tk.StringVar()
    search_frame = tk.Frame(stat_win, bg="#f5f6fa")
    search_frame.pack(fill=tk.X, padx=10, pady=(0, 8))
    tk.Label(search_frame, text="搜索：", font=("微软雅黑", 11), bg="#f5f6fa").pack(side=tk.LEFT)
    search_entry = tk.Entry(search_frame, textvariable=search_var, font=("微软雅黑", 11), width=30)
    search_entry.pack(side=tk.LEFT, padx=5)
    frame = tk.Frame(stat_win, bg="#f5f6fa")
    frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    columns = ("扩展名", "默认程序（打开命令）")
    style = ttk.Style()
    style.theme_use("default")
    style.configure("Treeview", font=("微软雅黑", 11), rowheight=28, background="#f5f6fa", fieldbackground="#f5f6fa")
    style.configure("Treeview.Heading", font=("微软雅黑", 12, "bold"), background="#dfe6e9", foreground="#2d3436")
    tree = ttk.Treeview(frame, columns=columns, show="headings")
    tree.heading("扩展名", text="扩展名")
    tree.heading("默认程序（打开命令）", text="默认程序（打开命令）")
    tree.column("扩展名", width=120, anchor="center")
    tree.column("默认程序（打开命令）", width=620, anchor="w")
    tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
    scrollbar = tk.Scrollbar(frame, orient="vertical", command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    def update_treeview(filter_text=""):
        tree.delete(*tree.get_children())
        for ext, cmd in stats:
            if filter_text:
                if filter_text.lower() in ext.lower() or filter_text.lower() in str(cmd).lower():
                    tree.insert("", tk.END, values=(ext, cmd))
            else:
                tree.insert("", tk.END, values=(ext, cmd))
    def on_search(*args):
        filter_text = search_var.get().strip()
        update_treeview(filter_text)
    search_var.trace_add("write", on_search)
    update_treeview()
def show_file_select(extension_entry):
    # 自动识别扩展名
    file_path = filedialog.askopenfilename(title="选择任意文件以识别扩展名")
    if file_path:
        _, ext = os.path.splitext(file_path)
        if ext:
            extension_entry.delete(0, tk.END)
            extension_entry.insert(0, ext)
            messagebox.showinfo("识别成功", f"已识别扩展名: {ext}")
        else:
            messagebox.showwarning("提示", "未识别到文件扩展名")
def set_folder_icon(folder_path, icon_path):
    """
    设置指定文件夹的图标为 icon_path（.ico 文件），ico 会被复制到文件夹内并永久保留
    """
    try:
        folder_path = os.path.abspath(folder_path)
        icon_path = os.path.abspath(icon_path)
        if not os.path.isdir(folder_path):
            messagebox.showerror("失败", f"文件夹不存在: {folder_path}")
            return
        if not os.path.isfile(icon_path):
            messagebox.showerror("失败", f"图标文件不存在: {icon_path}")
            return
        # 复制ico到文件夹内
        ico_name = "folder_icon.ico"
        dst_ico_path = os.path.join(folder_path, ico_name)
        if os.path.abspath(icon_path) != os.path.abspath(dst_ico_path):
            shutil.copyfile(icon_path, dst_ico_path)
        # desktop.ini 路径
        ini_path = os.path.join(folder_path, "desktop.ini")
        # 先移除 desktop.ini 的只读/隐藏/系统属性（如果存在）
        if os.path.exists(ini_path):
            os.system(f'attrib -s -h -r "{ini_path}"')
        # 用UTF-16 LE BOM写入desktop.ini，引用相对路径
        ini_content = f"""[.ShellClassInfo]
IconResource={ico_name},0
[ViewState]
Mode=
Vid=
FolderType=Generic
"""
        try:
            with open(ini_path, "w", encoding="utf-16") as f:
                f.write(ini_content)
        except PermissionError:
            messagebox.showerror("失败", f"没有权限写入 desktop.ini，请用管理员权限运行或选择有写权限的文件夹。")
            return
        # 设置 desktop.ini、ico 和文件夹属性为系统+隐藏
        os.system(f'attrib +s +h "{ini_path}"')
        os.system(f'attrib +s +h "{dst_ico_path}"')
        os.system(f'attrib +s "{folder_path}"')
        # 刷新资源管理器
        try:
            ctypes.windll.shell32.SHChangeNotify(0x8000000, 0x1000, None, None)
        except Exception:
            pass
        messagebox.showinfo("成功", f"已将文件夹\n{folder_path}\n的图标更换为:\n{dst_ico_path}\n如未生效请重启电脑或注销。")
    except Exception as e:
        messagebox.showerror("失败", f"设置文件夹图标失败: {e}")
def convert_image_to_ico(image_path, output_folder):
    """
    将任意图片转换为 256x256 的 .ico 文件，返回 ico 路径
    """
    try:
        img = Image.open(image_path)
        # 转为 RGBA，防止透明背景丢失
        if img.mode != "RGBA":
            img = img.convert("RGBA")
        ico_path = os.path.join(output_folder, "folder_icon_temp.ico")
        img.save(ico_path, format="ICO", sizes=[(256, 256)])
        return ico_path
    except Exception as e:
        messagebox.showerror("失败", f"图片转ico失败: {e}")
        return None
def show_set_folder_icon_dialog():
    #选择要更换图标的文件夹
    folder = filedialog.askdirectory(title="选择要更换图标的文件夹")
    if not folder:
        return
    img_path = filedialog.askopenfilename(
        title="选择图片（支持png/jpg/jpeg/bmp/gif/ico）",
        filetypes=[
            ("图片文件", "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.ico"),
            ("所有文件", "*.*")
        ]
    )
    if not img_path:
        return
    ext = os.path.splitext(img_path)[1].lower()
    if ext == ".ico":
        ico_path = img_path
    else:
        ico_path = convert_image_to_ico(img_path, folder)
    if ico_path:
        set_folder_icon(folder, ico_path)
COMMUNITY_API_BASE = "http://116.62.80.32" 
# 记住已登录的用户
community_user_info = {"username": None, "password": None}
def show_login_register_dialog(parent):
    global community_user_info
    login_win = tk.Toplevel(parent)
    login_win.title("登录/注册规则空间")
    login_win.geometry("370x220")
    login_win.resizable(False, False)
    login_win.grab_set()
    login_win.configure(bg="#f5f6fa")
    tk.Label(login_win, text="用户名：", font=("微软雅黑", 12), bg="#f5f6fa").place(x=30, y=30)
    username_entry = tk.Entry(login_win, font=("微软雅黑", 12), width=18)
    username_entry.place(x=110, y=30)
    tk.Label(login_win, text="密码：", font=("微软雅黑", 12), bg="#f5f6fa").place(x=30, y=70)
    password_entry = tk.Entry(login_win, font=("微软雅黑", 12), width=18, show="*")
    password_entry.place(x=110, y=70)
    result = {"username": None, "password": None}
    def do_login():
        #登录
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        if not username or not password:
            messagebox.showwarning("提示", "请输入用户名和密码", parent=login_win)
            return
        try:
            resp = requests.post(f"{COMMUNITY_API_BASE}/login", json={
                "username": username,
                "password": password
            }, timeout=10)
            if resp.status_code == 200:
                result["username"] = username
                result["password"] = password
                community_user_info["username"] = username
                community_user_info["password"] = password
                login_win.destroy()
            else:
                messagebox.showerror("登录失败", resp.json().get("error", "未知错误"), parent=login_win)
        except Exception as e:
            messagebox.showerror("登录失败", f"网络异常: {e}", parent=login_win)
    def do_register():
        #注册
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        if not username or not password:
            messagebox.showwarning("提示", "请输入用户名和密码", parent=login_win)
            return
        try:
            resp = requests.post(f"{COMMUNITY_API_BASE}/register", json={
                "username": username,
                "password": password
            }, timeout=10)
            if resp.status_code == 200:
                messagebox.showinfo("注册成功", "注册成功，请点击登录", parent=login_win)
            else:
                messagebox.showerror("注册失败", resp.json().get("error", "未知错误"), parent=login_win)
        except Exception as e:
            messagebox.showerror("注册失败", f"网络异常: {e}")
    btn_style = {"font": ("微软雅黑", 11, "bold"), "bg": "#0984e3", "fg": "white", "activebackground": "#74b9ff", "activeforeground": "#2d3436", "relief": "flat", "bd": 0, "height": 1}
    tk.Button(login_win, text="登录", width=10, command=do_login, **btn_style).place(x=60, y=130)
    tk.Button(login_win, text="注册", width=10, command=do_register, bg="#00b894", activebackground="#55efc4", **{k: v for k, v in btn_style.items() if k not in ["bg", "activebackground"]}).place(x=180, y=130)
    login_win.wait_window()
    return result["username"], result["password"]
def show_change_password_dialog(parent, username):
    global community_user_info
    win = tk.Toplevel(parent)
    win.title("修改密码")
    #窗口大小
    win.geometry("500x260")
    win.resizable(False, False)
    win.grab_set()
    win.configure(bg="#f5f6fa")
    giraffe_canvas = tk.Canvas(win, width=60, height=80, bg="#f5f6fa", highlightthickness=0)
    giraffe_canvas.place(x=0, y=0)
    giraffe_canvas.create_rectangle(25, 25, 35, 70, fill="#ffeaa7", outline="#fdcb6e", width=2)
    for y in range(32, 70, 14):
        giraffe_canvas.create_oval(27, y, 33, y+8, fill="#fdcb6e", outline="#fdcb6e")
    giraffe_canvas.create_oval(15, 5, 45, 35, fill="#ffeaa7", outline="#fdcb6e", width=2)
    giraffe_canvas.create_oval(12, 3, 20, 13, fill="#ffeaa7", outline="#fdcb6e", width=1)
    giraffe_canvas.create_oval(40, 3, 48, 13, fill="#fdcb6e", outline="#fdcb6e", width=1)
    giraffe_canvas.create_line(22, 8, 18, 0, fill="#fdcb6e", width=2)
    giraffe_canvas.create_line(38, 8, 42, 0, fill="#fdcb6e", width=2)
    giraffe_canvas.create_oval(16, -2, 20, 2, fill="#fdcb6e", outline="#fdcb6e")
    giraffe_canvas.create_oval(40, -2, 44, 2, fill="#fdcb6e", outline="#fdcb6e")
    giraffe_canvas.create_oval(25, 17, 29, 21, fill="#636e72", outline="")
    giraffe_canvas.create_oval(31, 17, 35, 21, fill="#636e72", outline="")
    tk.Label(win, text=f"用户名：{username}", font=("微软雅黑", 12), bg="#f5f6fa").place(x=90, y=30)
    # 原密码输入框
    old_frame = tk.Frame(win, bg="#f5f6fa")
    old_frame.place(x=80, y=70)
    old_canvas = tk.Canvas(old_frame, width=16, height=32, bg="#f5f6fa", highlightthickness=0)
    old_canvas.pack(side=tk.LEFT, fill=tk.Y)
    old_canvas.create_rectangle(6, 0, 10, 32, fill="#ffeaa7", outline="#fdcb6e", width=2)
    old_pwd_entry = tk.Entry(
        old_frame,
        font=("微软雅黑", 12, "bold"),
        width=16,
        show="*",
        bg="#fffbe6",
        relief="flat",
        highlightthickness=2,
        highlightbackground="#fdcb6e",
        highlightcolor="#fdcb6e",
        borderwidth=0,
        fg="#636e72"
    )
    old_pwd_entry.pack(side=tk.LEFT, ipady=4, ipadx=2, padx=(0, 0))
    tk.Label(old_frame, text="原密码", font=("微软雅黑", 11), bg="#f5f6fa", fg="#0984e3").pack(side=tk.LEFT, padx=(6, 0))
    # 新密码输入框
    new_frame = tk.Frame(win, bg="#f5f6fa")
    new_frame.place(x=80, y=120)
    new_canvas = tk.Canvas(new_frame, width=16, height=32, bg="#f5f6fa", highlightthickness=0)
    new_canvas.pack(side=tk.LEFT, fill=tk.Y)
    new_canvas.create_rectangle(6, 0, 10, 32, fill="#ffeaa7", outline="#fdcb6e", width=2)
    new_pwd_entry = tk.Entry(
        new_frame,
        font=("微软雅黑", 12, "bold"),
        width=16,
        show="*",
        bg="#fffbe6",
        relief="flat",
        highlightthickness=2,
        highlightbackground="#fdcb6e",
        highlightcolor="#fdcb6e",
        borderwidth=0,
        fg="#636e72"
    )
    new_pwd_entry.pack(side=tk.LEFT, ipady=4, ipadx=2, padx=(0, 0))
    tk.Label(new_frame, text="新密码", font=("微软雅黑", 11), bg="#f5f6fa", fg="#0984e3").pack(side=tk.LEFT, padx=(6, 0))
    def do_change():
        old_pwd = old_pwd_entry.get().strip()
        new_pwd = new_pwd_entry.get().strip()
        if not old_pwd or not new_pwd:
            messagebox.showwarning("提示", "请输入原密码和新密码", parent=win)
            return
        try:
            resp = requests.post(f"{COMMUNITY_API_BASE}/change_password", json={
                "username": username,
                "old_password": old_pwd,
                "new_password": new_pwd
            }, timeout=10)
            if resp.status_code == 200:
                community_user_info["password"] = new_pwd
                messagebox.showinfo("修改成功", "密码修改成功，已自动更新登录状态", parent=win)
                win.destroy()
            else:
                messagebox.showerror("修改失败", resp.json().get("error", "未知错误"), parent=win)
        except Exception as e:
            messagebox.showerror("修改失败", f"网络异常: {e}")
    btn_style = {"font": ("微软雅黑", 11, "bold"), "bg": "#fdcb6e", "fg": "#2d3436", "activebackground": "#ffeaa7", "relief": "flat", "bd": 0, "height": 1}
    tk.Button(win, text="修改密码", width=16, command=do_change, **btn_style).place(x=140, y=180)
    win.wait_window()
def show_rule_detail_dialog(parent, rule_info, rule_content, on_apply_callback=None):
    """
    精美弹窗展示规则详情，支持一键应用，并显示标签内容
    """
    win = tk.Toplevel(parent)
    win.title(f"规则详情 - {rule_info.get('name', '')}")
    win.geometry("600x520")
    win.resizable(False, False)
    win.grab_set()
    # 标题
    tk.Label(win, text=f"规则名称：{rule_info.get('name', '')}", font=("微软雅黑", 14, "bold")).pack(pady=(18, 4))
    tk.Label(win, text=f"作者：{rule_info.get('username', '')}", font=("微软雅黑", 12)).pack()
    tk.Label(win, text=f"简介：{rule_info.get('desc', '')}", font=("微软雅黑", 11), fg="#636e72").pack(pady=(0, 4))
    # 标签内容
    tags = rule_info.get("tags", [])
    tags_str = ", ".join(tags) if tags else "无"
    tk.Label(win, text=f"标签：{tags_str}", font=("微软雅黑", 11), fg="#00b894").pack(pady=(0, 10))
    # 规则内容展示
    frame = tk.Frame(win)
    frame.pack(fill=tk.BOTH, expand=True, padx=18, pady=8)
    txt = tk.Text(frame, font=("Consolas", 11), height=14, wrap="none", bg="#f8f8f8")
    txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar = tk.Scrollbar(frame, command=txt.yview)
    txt.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    # 格式化内容
    pretty = json.dumps(rule_content, ensure_ascii=False, indent=2)
    txt.insert(tk.END, pretty)
    txt.config(state=tk.DISABLED)
    # 下载并应用按钮
    def do_apply():
        # 新增：只应用本地能找到程序的规则
        applied = apply_rules_with_smart_path(rule_content)
        if applied == 0:
            messagebox.showwarning("未应用", "未找到任何本地可用的程序，未应用任何规则。", parent=win)
        else:
            messagebox.showinfo("应用成功", f"已成功应用 {applied} 条本地可用规则。", parent=win)
        if on_apply_callback:
            on_apply_callback(rule_content)
        win.destroy()
    btn = tk.Button(win, text="下载并应用此规则", font=("微软雅黑", 12, "bold"), bg="#00b894", fg="white", width=20, command=do_apply)
    btn.pack(pady=18)
    tk.Button(win, text="关闭", font=("微软雅黑", 11), width=10, command=win.destroy).pack()
    win.wait_window()
def show_rule_community():
    global community_user_info
    win = tk.Toplevel()
    win.title("规则空间")
    win.geometry("800x560")
    win.configure(bg="#f5f6fa")

    # ======= 顶部欢迎与统计区 =======
    stats_frame = tk.Frame(win, bg="#f5f6fa")
    stats_frame.pack(fill=tk.X, pady=(18, 8))

    # 自动登录
    if community_user_info["username"] and community_user_info["password"]:
        username = community_user_info["username"]
        password = community_user_info["password"]
    else:
        root = tk._default_root
        username, password = show_login_register_dialog(root)
        if not username or not password:
            return
        community_user_info["username"] = username
        community_user_info["password"] = password

    # ======= 精致统计卡片 =======
    stat_card = tk.Frame(stats_frame, bg="#fff", bd=0, highlightbackground="#e0e0e0", highlightthickness=1)
    stat_card.pack(anchor="w", padx=24, pady=(0, 0))

    # 左侧图标
    icon_label = tk.Label(stat_card, text="🗂️", font=("Segoe UI Emoji", 28), bg="#fff")
    icon_label.grid(row=0, column=0, rowspan=2, padx=(22, 16), pady=18)

    # 获取统计数据
    rule_count = 0
    user_count = 0
    try:
        resp = requests.get(f"{COMMUNITY_API_BASE}/stats", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            rule_count = data.get("rule_count", 0)
            user_count = data.get("user_count", 0)
    except Exception:
        pass

    # 欢迎语
    welcome_label = tk.Label(
        stat_card,
        text=f"欢迎回来，{username}",
        font=("微软雅黑", 18, "bold"),
        bg="#fff",
        fg="#222"
    )
    welcome_label.grid(row=0, column=1, sticky="w", padx=(0, 0), pady=(18, 0))

    # 统计数字
    stat_font = ("微软雅黑", 15, "bold")
    stat_val_font = ("微软雅黑", 22, "bold")
    stat_fg = "#2176ff"
    tk.Label(stat_card, text="空间规则总数", font=stat_font, bg="#fff", fg="#888").grid(row=1, column=1, sticky="w", padx=(0, 24), pady=(4, 18))
    tk.Label(stat_card, text=f"{rule_count:,}", font=stat_val_font, bg="#fff", fg=stat_fg).grid(row=1, column=2, sticky="w", padx=(0, 36), pady=(4, 18))
    tk.Label(stat_card, text="注册用户数", font=stat_font, bg="#fff", fg="#888").grid(row=1, column=3, sticky="w", padx=(0, 24), pady=(4, 18))
    tk.Label(stat_card, text=f"{user_count:,}", font=stat_val_font, bg="#fff", fg=stat_fg).grid(row=1, column=4, sticky="w", padx=(0, 24), pady=(4, 18))

    # 分割线
    sep = tk.Frame(win, bg="#e0e0e0", height=2)
    sep.pack(fill=tk.X, padx=24, pady=(2, 8))

    # ...existing code for user_frame, upload_frame, filter_frame, browse_frame, etc...
    user_frame = tk.Frame(win, bg="#f5f6fa")
    user_frame.pack(side=tk.BOTTOM, fill=tk.X, pady=(0, 8))
    tk.Label(user_frame, text=f"当前用户：{username}", font=("微软雅黑", 11, "bold"), fg="#636e72", bg="#f5f6fa").pack(side=tk.LEFT, padx=18)
    def on_change_pwd():
        show_change_password_dialog(win, username)
    tk.Button(user_frame, text="修改密码", font=("微软雅黑", 10, "bold"), bg="#fdcb6e", fg="#2d3436", activebackground="#ffeaa7", relief="flat", bd=0, height=1, command=on_change_pwd).pack(side=tk.LEFT, padx=18)
    def on_logout():
        community_user_info["username"] = None
        community_user_info["password"] = None
        win.destroy()
    tk.Button(user_frame, text="退出登录", font=("微软雅黑", 10, "bold"), bg="#d63031", fg="white", activebackground="#fab1a0", relief="flat", bd=0, height=1, command=on_logout).pack(side=tk.LEFT, padx=18)
    # 上传区
    upload_frame = tk.LabelFrame(win, text="上传本地JSON规则", font=("微软雅黑", 12, "bold"), bg="#f5f6fa")
    upload_frame.pack(fill=tk.X, padx=18, pady=(16, 8))
    # 只保留上传本地JSON规则按钮
    tk.Label(upload_frame, text="请选择本地JSON规则文件：", font=("微软雅黑", 11), bg="#f5f6fa").grid(row=0, column=0, sticky="e", padx=5, pady=5)
    selected_json_path = tk.StringVar()
    json_entry = tk.Entry(upload_frame, font=("微软雅黑", 11), width=38, textvariable=selected_json_path, state="readonly")
    json_entry.grid(row=0, column=1, padx=5, pady=5)
    # 用于缓存已加载的规则
    loaded_local_rules = {"rules": None}
    def select_json_file():
        file = filedialog.askopenfilename(
            filetypes=[("JSON 文件", "*.json")],
            title="选择要上传的规则JSON文件",
            parent=win
        )
        if file:
            selected_json_path.set(file)
            try:
                with open(file, "r", encoding="utf-8") as f:
                    local_rules = json.load(f)
                # 兼容：如果local_rules是规则对象（带有name/desc/rules等），自动提取rules字段
                if (isinstance(local_rules, list) and len(local_rules) == 1 and isinstance(local_rules[0], dict)
                    and "rules" in local_rules[0] and isinstance(local_rules[0]["rules"], list)):
                    local_rules = local_rules[0]["rules"]
                # 检查每条规则格式
                for r in local_rules:
                    if not (isinstance(r, dict) and "ext" in r and "app" in r and "priority" in r):
                        messagebox.showerror("格式错误", "JSON规则列表格式不正确", parent=win)
                        loaded_local_rules["rules"] = None
                        return
                loaded_local_rules["rules"] = local_rules
                messagebox.showinfo("加载成功", "规则文件已加载，请填写规则名称、简介和标签后提交。", parent=win)
            except Exception as e:
                loaded_local_rules["rules"] = None
                messagebox.showerror("加载失败", f"读取本地规则失败: {e}", parent=win)
    tk.Button(upload_frame, text="选择JSON规则文件", command=select_json_file, font=("微软雅黑", 11), bg="#0984e3", fg="white", width=18).grid(row=0, column=2, padx=8, pady=5)
    # 规则名称、简介、标签输入
    tk.Label(upload_frame, text="规则名称：", font=("微软雅黑", 11), bg="#f5f6fa").grid(row=1, column=0, sticky="e", padx=5, pady=5)
    name_entry = tk.Entry(upload_frame, font=("微软雅黑", 11), width=18)
    name_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
    tk.Label(upload_frame, text="简介：", font=("微软雅黑", 11), bg="#f5f6fa").grid(row=1, column=2, sticky="e", padx=5, pady=5)
    desc_entry = tk.Entry(upload_frame, font=("微软雅黑", 11), width=28)
    desc_entry.grid(row=1, column=3, padx=5, pady=5, sticky="w")
    tk.Label(upload_frame, text="标签（逗号分隔）：", font=("微软雅黑", 11), bg="#f5f6fa").grid(row=1, column=4, sticky="e", padx=5, pady=5)
    tags_entry = tk.Entry(upload_frame, font=("微软雅黑", 11), width=18)
    tags_entry.grid(row=1, column=5, padx=5, pady=5, sticky="w")
    def do_upload():
        rules_to_upload = loaded_local_rules["rules"]
        if not rules_to_upload:
            messagebox.showwarning("提示", "请先选择并加载本地JSON规则文件", parent=win)
            return
        name_val = name_entry.get().strip()
        desc_val = desc_entry.get().strip()
        tags_val = tags_entry.get().strip()
        tags_list = [t.strip() for t in tags_val.split(",") if t.strip()]
        if not name_val:
            messagebox.showwarning("提示", "请填写规则名称", parent=win)
            return
        try:
            resp = requests.post(f"{COMMUNITY_API_BASE}/upload", json={
                "username": username,
                "password": password,
                "name": name_val,
                "desc": desc_val,
                "rules": rules_to_upload,
                "tags": tags_list
            }, timeout=10)
            if resp.status_code == 200:
                messagebox.showinfo("上传成功", "规则已上传到空间！", parent=win)
                # 清空输入
                selected_json_path.set("")
                name_entry.delete(0, tk.END)
                desc_entry.delete(0, tk.END)
                tags_entry.delete(0, tk.END)
                loaded_local_rules["rules"] = None
            else:
                messagebox.showerror("上传失败", resp.json().get("error", f"服务器返回: {resp.status_code}"), parent=win)
        except Exception as e:
            messagebox.showerror("上传失败", f"网络异常: {e}")
    submit_btn = tk.Button(
        upload_frame,
        text="提交规则到空间",
        command=do_upload,
        font=("微软雅黑", 12, "bold"),
        bg="#00b894",
        fg="white",
        width=16,
        relief="flat",
        activebackground="#55efc4",
        activeforeground="#2d3436",
        bd=0,
        cursor="hand2",
        highlightthickness=0
    )
    submit_btn.grid(row=1, column=6, padx=12, pady=5)
    submit_btn.bind("<Enter>", lambda e: submit_btn.config(bg="#26de81"))
    submit_btn.bind("<Leave>", lambda e: submit_btn.config(bg="#00b894"))
    # 标签筛选与搜索
    filter_frame = tk.Frame(win, bg="#f5f6fa")
    filter_frame.pack(fill=tk.X, padx=18, pady=(8, 0))
    tk.Label(filter_frame, text="标签筛选：", font=("微软雅黑", 11), bg="#f5f6fa").pack(side=tk.LEFT)
    tag_var = tk.StringVar()
    tag_entry = tk.Entry(filter_frame, textvariable=tag_var, font=("微软雅黑", 11), width=12)
    tag_entry.pack(side=tk.LEFT, padx=4)
    tk.Label(filter_frame, text="关键词搜索：", font=("微软雅黑", 11), bg="#f5f6fa").pack(side=tk.LEFT, padx=(18,0))
    search_var = tk.StringVar()
    search_entry = tk.Entry(filter_frame, textvariable=search_var, font=("微软雅黑", 11), width=16)
    search_entry.pack(side=tk.LEFT, padx=4)
    # 搜索按钮
    search_btn = tk.Button(filter_frame, text="搜索", font=("微软雅黑", 10), width=8, command=lambda: refresh_community())
    search_btn.pack(side=tk.LEFT, padx=8)
    # 浏览
    browse_frame = tk.LabelFrame(win, text="浏览/下载空间的规则", font=("微软雅黑", 12, "bold"), bg="#f5f6fa")
    browse_frame.pack(fill=tk.BOTH, expand=True, padx=18, pady=(0, 12))
    columns = ("ID", "规则名称", "简介", "作者", "评分人数", "平均评分", "标签")
    tree = ttk.Treeview(browse_frame, columns=columns, show="headings", height=14)
    for col, w in zip(columns, (60, 180, 180, 100, 80, 80, 120)):
        tree.heading(col, text=col)
        tree.column(col, width=w, anchor="center")
    tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=5, pady=5)
    scrollbar = tk.Scrollbar(browse_frame, orient="vertical", command=tree.yview)
    tree.configure(yscroll=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    def refresh_community():
        tree.delete(*tree.get_children())
        params = {}
        if search_var.get().strip():
            params["search"] = search_var.get().strip()
        # 标签筛选模糊匹配
        try:
            resp = requests.get(f"{COMMUNITY_API_BASE}/rules", params=params, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                rules_list = data["rules"] if isinstance(data, dict) and "rules" in data else data
                def get_avg(item):
                    try:
                        return float(item.get("avg_score", 0))
                    except Exception:
                        return 0
                rules_list = sorted(rules_list, key=get_avg, reverse=True)
                tag_filter = tag_var.get().strip().lower()
                for item in rules_list:
                    tags = item.get("tags", [])
                    tags_str = ", ".join(tags) if tags else ""
                    # 本地模糊标签筛选
                    if tag_filter:
                        if not any(tag_filter in t.lower() for t in tags):
                            continue
                    tree.insert(
                        "",
                        tk.END,
                        values=(
                            item.get("id"),
                            item.get("name"),
                            item.get("desc"),
                            item.get("username", ""),
                            item.get("score_count", 0),
                            "{:.2f}".format(float(item.get("avg_score", 0))) if "avg_score" in item else "0.00",
                            tags_str
                        )
                    )
            else:
                messagebox.showerror("加载失败", f"服务器返回: {resp.status_code}")
        except Exception as e:
            messagebox.showerror("加载失败", f"网络异常: {e}")
    tag_entry.bind("<Return>", lambda e: refresh_community())
    search_entry.bind("<Return>", lambda e: refresh_community())
    search_btn.config(command=refresh_community)
    # 评分
    def rate_selected_rule():
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择一条规则")
            return
        item = tree.item(sel[0])
        rule_id = item["values"][0]
        score = simpledialog.askinteger("规则评分", "请输入评分（1-5分）", minvalue=1, maxvalue=5, parent=win)
        if not score:
            return
        try:
            resp = requests.post(f"{COMMUNITY_API_BASE}/rate", json={
                "rule_id": rule_id,
                "score": score,
                "username": username
            }, timeout=10)
            if resp.status_code == 200:
                messagebox.showinfo("评分成功", "感谢您的评分！")
                refresh_community()
            else:
                messagebox.showerror("评分失败", f"服务器返回: {resp.status_code}")
        except Exception as e:
            messagebox.showerror("评分失败", f"网络异常: {e}")
    def refresh_community():
        tree.delete(*tree.get_children())
        try:
            resp = requests.get(f"{COMMUNITY_API_BASE}/rules", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                rules_list = data["rules"] if isinstance(data, dict) and "rules" in data else data
                def get_avg(item):
                    try:
                        return float(item.get("avg_score", 0))
                    except Exception:
                        return 0
                rules_list = sorted(rules_list, key=get_avg, reverse=True)
                for item in rules_list:
                    tree.insert(
                        "",
                        tk.END,
                        values=(
                            item.get("id"),
                            item.get("name"),
                            item.get("desc"),
                            item.get("username", ""),
                            item.get("score_count", 0),
                            "{:.2f}".format(float(item.get("avg_score", 0))) if "avg_score" in item else "0.00"
                        )
                    )
            else:
                messagebox.showerror("加载失败", f"服务器返回: {resp.status_code}")
        except Exception as e:
            messagebox.showerror("加载失败", f"网络异常: {e}")
    def download_selected():
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择一条规则")
            return
        item = tree.item(sel[0])
        rule_id = item["values"][0]
        try:
            resp = requests.get(f"{COMMUNITY_API_BASE}/rule/{rule_id}", timeout=10)
            if resp.status_code == 200:
                imported = resp.json()
                imported_rules = imported["rules"] if isinstance(imported, dict) and "rules" in imported else imported
                author = imported.get("username", "")
                rule_name = imported.get("name", "")
                if isinstance(imported_rules, list):
                    applied = apply_rules_with_smart_path(imported_rules)
                    if applied == 0:
                        messagebox.showwarning("未应用", "未找到任何本地可用的程序，未应用任何规则。")
                    else:
                        messagebox.showinfo("导入成功", f"规则已成功导入并应用 {applied} 条！\n作者：{author}\n规则名：{rule_name}")
                else:
                    messagebox.showerror("导入失败", "规则格式不正确")
            else:
                messagebox.showerror("下载失败", f"服务器返回: {resp.status_code}")
        except Exception as e:
            messagebox.showerror("下载失败", f"网络异常: {e}")
    def on_rule_double_click(event):
        sel = tree.selection()
        if not sel:
            return
        item = tree.item(sel[0])
        rule_id = item["values"][0]
        try:
            resp = requests.get(f"{COMMUNITY_API_BASE}/rule/{rule_id}", timeout=10)
            if resp.status_code == 200:
                rule_detail = resp.json()
                # 弹窗显示规则详情和json内容
                def show_json_content():
                    win_json = tk.Toplevel(win)
                    win_json.title("规则 JSON 文件内容")
                    win_json.geometry("700x500")
                    win_json.grab_set()
                    txt = tk.Text(win_json, font=("Consolas", 11), wrap="none", bg="#f8f8f8")
                    txt.pack(fill=tk.BOTH, expand=True)
                    pretty = json.dumps(rule_detail.get("rules", []), ensure_ascii=False, indent=2)
                    txt.insert(tk.END, pretty)
                    txt.config(state=tk.DISABLED)
                    tk.Button(win_json, text="关闭", font=("微软雅黑", 11), width=10, command=win_json.destroy).pack(pady=8)
                    win_json.wait_window()
                # 规则详情弹窗
                detail_win = tk.Toplevel(win)
                detail_win.title(f"规则详情 - {rule_detail.get('name', '')}")
                detail_win.geometry("600x520")
                detail_win.resizable(False, False)
                detail_win.grab_set()
                tk.Label(detail_win, text=f"规则名称：{rule_detail.get('name', '')}", font=("微软雅黑", 14, "bold")).pack(pady=(18, 4))
                tk.Label(detail_win, text=f"作者：{rule_detail.get('username', '')}", font=("微软雅黑", 12)).pack()
                tk.Label(detail_win, text=f"简介：{rule_detail.get('desc', '')}", font=("微软雅黑", 11), fg="#636e72").pack(pady=(0, 4))
                tags = rule_detail.get("tags", [])
                tags_str = ", ".join(tags) if tags else "无"
                tk.Label(detail_win, text=f"标签：{tags_str}", font=("微软雅黑", 11), fg="#00b894").pack(pady=(0, 10))
                frame = tk.Frame(detail_win)
                frame.pack(fill=tk.BOTH, expand=True, padx=18, pady=8)
                txt = tk.Text(frame, font=("Consolas", 11), height=14, wrap="none", bg="#f8f8f8")
                txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                scrollbar = tk.Scrollbar(frame, command=txt.yview)
                txt.configure(yscrollcommand=scrollbar.set)
                scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
                pretty = json.dumps(rule_detail.get("rules", []), ensure_ascii=False, indent=2)
                txt.insert(tk.END, pretty)
                txt.config(state=tk.DISABLED)
                btn_frame = tk.Frame(detail_win)
                btn_frame.pack(pady=12)
                tk.Button(btn_frame, text="查看完整JSON内容", font=("微软雅黑", 11), width=18, command=show_json_content).pack(side=tk.LEFT, padx=8)
                tk.Button(btn_frame, text="关闭", font=("微软雅黑", 11), width=10, command=detail_win.destroy).pack(side=tk.LEFT, padx=8)
                detail_win.wait_window()
            else:
                messagebox.showerror("加载失败", f"服务器返回: {resp.status_code}")
        except Exception as e:
            messagebox.showerror("加载失败", f"网络异常: {e}")

    tree.bind("<Double-1>", on_rule_double_click)
    # 举报
    def report_selected_rule():
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择一条规则")
            return
        item = tree.item(sel[0])
        rule_id = item["values"][0]
        reason = simpledialog.askstring("举报理由", "请输入举报理由：", parent=win)
        if not reason:
            return
        try:
            resp = requests.post(f"{COMMUNITY_API_BASE}/report", json={
                "rule_id": rule_id,
                "username": community_user_info["username"],
                "reason": reason
            }, timeout=10)
            if resp.status_code == 200:
                messagebox.showinfo("举报成功", "感谢您的举报，我们会尽快处理。")
            else:
                messagebox.showerror("举报失败", resp.json().get("error", f"服务器返回: {resp.status_code}"))
        except Exception as e:
            messagebox.showerror("举报失败", f"网络异常: {e}")
    # 标签编辑（仅自己规则可编辑）
    def edit_tags_selected_rule():
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择一条规则")
            return
        item = tree.item(sel[0])
        rule_id = item["values"][0]
        author = item["values"][3]
        if author != community_user_info["username"]:
            messagebox.showwarning("提示", "只能修改自己上传的规则标签")
            return
        # 获取当前标签
        tags_now = item["values"][6] if len(item["values"]) > 6 else ""
        tags_str = simpledialog.askstring("编辑标签", "请输入标签（多个标签用英文逗号分隔）", initialvalue=tags_now, parent=win)
        if tags_str is None:
            return
        tags = [t.strip() for t in tags_str.split(",") if t.strip()]
        try:
            resp = requests.post(f"{COMMUNITY_API_BASE}/set_tags", json={
                "rule_id": rule_id,
                "username": community_user_info["username"],
                "tags": tags
            }, timeout=10)
            if resp.status_code == 200:
                messagebox.showinfo("修改成功", "标签已更新")
                refresh_community()
            else:
                messagebox.showerror("修改失败", resp.json().get("error", f"服务器返回: {resp.status_code}"))
        except Exception as e:
            messagebox.showerror("修改失败", f"网络异常: {e}")
    # 删除规则（仅自己规则可删除）
    def delete_selected_rule():
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("提示", "请先选择一条规则")
            return
        item = tree.item(sel[0])
        rule_id = item["values"][0]
        author = item["values"][3]
        if author != community_user_info["username"]:
            messagebox.showwarning("提示", "只能删除自己上传的规则")
            return
        confirm = messagebox.askyesno("确认删除", "确定要删除这条规则吗？")
        if not confirm:
            return
        try:
            resp = requests.post(f"{COMMUNITY_API_BASE}/delete_rule", json={
                "rule_id": rule_id,
                "username": community_user_info["username"]
            }, timeout=10)
            if resp.status_code == 200:
                messagebox.showinfo("删除成功", "规则已删除")
                refresh_community()
            else:
                messagebox.showerror("删除失败", resp.json().get("error", f"服务器返回: {resp.status_code}"))
        except Exception as e:
            messagebox.showerror("删除失败", f"网络异常: {e}")
    btn_frame = tk.Frame(browse_frame, bg="#f5f6fa")
    btn_frame.pack(fill=tk.X, pady=5)
    def make_beauty_btn(text, cmd, bg, fg, hover_bg, width=14):
        btn = tk.Button(
            btn_frame,
            text=text,
            command=cmd,
            font=("微软雅黑", 11, "bold"),
            bg=bg,
            fg=fg,
            width=width,
            relief="flat",
            activebackground=hover_bg,
            activeforeground="#222",
            bd=0,
            cursor="hand2",
            highlightthickness=0
        )
        btn.pack(side=tk.LEFT, padx=10)
        btn.bind("<Enter>", lambda e: btn.config(bg=hover_bg))
        btn.bind("<Leave>", lambda e: btn.config(bg=bg))
        return btn
    make_beauty_btn("刷新列表", refresh_community, "#0984e3", "white", "#74b9ff", 12)
    make_beauty_btn("下载并应用选中规则", download_selected, "#fdcb6e", "#2d3436", "#ffeaa7", 18)
    make_beauty_btn("给选中规则评分", rate_selected_rule, "#00b894", "white", "#55efc4", 14)
    make_beauty_btn("编辑标签", edit_tags_selected_rule, "#636e72", "white", "#b2bec3", 12)
    make_beauty_btn("删除选中规则", delete_selected_rule, "#d63031", "white", "#fab1a0", 14)
    make_beauty_btn("举报选中规则", report_selected_rule, "#d63031", "white", "#fab1a0", 14)
    refresh_community()
def set_folder_password(folder_path, password):
    """
    给文件夹设置密码：将所有内容移入 .__locked_content__ 子目录，用户输入密码前无法访问
    """
    try:
        folder_path = os.path.abspath(folder_path)
        if not os.path.isdir(folder_path):
            messagebox.showerror("失败", f"文件夹不存在: {folder_path}")
            return
        hidden_dir = os.path.join(folder_path, ".__locked_content__")
        if os.path.exists(hidden_dir):
            messagebox.showerror("失败", "该目录已加密")
            return
        # 创建隐藏内容目录
        os.mkdir(hidden_dir)
        # 移动所有非提示/lock/.__locked_content__文件到隐藏目录
        for name in os.listdir(folder_path):
            if name not in ["请用文件默认大师解锁.txt", ".folderlock", ".__locked_content__"]:
                src = os.path.join(folder_path, name)
                dst = os.path.join(hidden_dir, name)
                os.rename(src, dst)
        # 创建提示文件
        tip_file = os.path.join(folder_path, "请用文件默认大师解锁.txt")
        with open(tip_file, "w", encoding="utf-8") as f:
            f.write("该目录已加密，请用文件默认大师输入密码解锁访问。")
        # 保存密码hash
        pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        hash_file = os.path.join(folder_path, ".folderlock")
        with open(hash_file, "w") as f:
            f.write(pwd_hash)
        os.system(f'attrib +h "{hash_file}"')
        # 隐藏 .__locked_content__ 目录
        os.system(f'attrib +h "{hidden_dir}"')
        messagebox.showinfo("成功", f"目录已加密，只有通过本工具取消密码才能恢复内容。")
    except Exception as e:
        messagebox.showerror("失败", f"设置目录密码失败: {e}")
def remove_folder_password(folder_path):
    """彻底移除目录密码并恢复所有内容
    """
    try:
        folder_path = os.path.abspath(folder_path)
        hash_file = os.path.join(folder_path, ".folderlock")
        tip_file = os.path.join(folder_path, "请用文件默认大师解锁.txt")
        hidden_dir = os.path.join(folder_path, ".__locked_content__")
        # 校验密码
        if not os.path.isfile(hash_file):
            messagebox.showerror("失败", "该目录未设置密码")
            return
        pwd = simpledialog.askstring("输入密码", "请输入目录密码：", show="*")
        if not pwd:
            return
        with open(hash_file, "r") as f:
            pwd_hash = f.read().strip()
        if hashlib.sha256(pwd.encode("utf-8")).hexdigest() != pwd_hash:
            messagebox.showerror("失败", "密码错误")
            return
        # 删除.lock和提示文件
        try:
            os.system(f'attrib -h "{hash_file}"')
            os.remove(hash_file)
        except Exception:
            pass
        try:
            os.remove(tip_file)
        except Exception:
            pass
        # 恢复所有内容
        if os.path.isdir(hidden_dir):
            os.system(f'attrib -h "{hidden_dir}"')
            for name in os.listdir(hidden_dir):
                src = os.path.join(hidden_dir, name)
                dst = os.path.join(folder_path, name)
                os.rename(src, dst)
            os.rmdir(hidden_dir)
        messagebox.showinfo("成功", f"已取消目录密码并恢复所有内容可见。")
    except Exception as e:
        messagebox.showerror("失败", f"取消目录密码失败: {e}")
def show_set_folder_password_dialog():
    folder = filedialog.askdirectory(title="选择要加密的文件夹")
    if not folder:
        return
    pwd = simpledialog.askstring("设置密码", "请输入要设置的密码：", show="*")
    if not pwd:
        return
    set_folder_password(folder, pwd)
def show_remove_folder_password_dialog():
    # 搜索所有含有 .folderlock 的目录
    search_root = filedialog.askdirectory(title="选择要搜索的根目录")
    if not search_root:
        return
    locked_dirs = []
    for root, dirs, files in os.walk(search_root):
        if ".folderlock" in files:
            locked_dirs.append(root)
    if not locked_dirs:
        messagebox.showinfo("未找到", "未找到加密目录")
        return
    sel = simpledialog.askstring("选择目录", "输入要取消密码的目录编号：\n" + "\n".join(f"{i+1}. {d}" for i, d in enumerate(locked_dirs)))
    if not sel or not sel.isdigit() or int(sel) < 1 or int(sel) > len(locked_dirs):
        return
    folder = locked_dirs[int(sel)-1]
    # 确认
    confirm = simpledialog.askstring("确认", f"是否取消目录密码？输入 yes/no：\n{folder}")
    if confirm and confirm.lower() == "yes":
        remove_folder_password(folder)
def create_gui():
    root = tb.Window(themename="cosmo") 
    root.title("文件默认大师")
    root.geometry("1020x620")  
    root.configure(bg="#f5f6fa")
    root.resizable(False, False)
    # 顶部标题栏
    title_frame = tk.Frame(root, bg="#f5f6fa")
    title_frame.grid(row=0, column=0, columnspan=5, pady=(18, 8), sticky="ew")
    logo = tk.Label(title_frame, text="🗂️", font=("Segoe UI Emoji", 28), bg="#f5f6fa")
    logo.pack(side=tk.LEFT, padx=(18, 8))
    title_label = tk.Label(title_frame, text="文件默认大师", font=("微软雅黑", 24, "bold"), fg="#273c75", bg="#f5f6fa")
    title_label.pack(side=tk.LEFT)
    subtitle = tk.Label(title_frame, text="— 让文件关联更简单", font=("微软雅黑", 13), fg="#636e72", bg="#f5f6fa")
    subtitle.pack(side=tk.LEFT, padx=(12, 0))
    # 主体区域
    card = tk.Frame(root, bg="#ffffff", bd=0, highlightbackground="#dfe6e9", highlightthickness=2)
    card.grid(row=1, column=0, columnspan=5, padx=28, pady=(0, 10), sticky="nsew")
    giraffe_canvas = tk.Canvas(card, width=80, height=120, bg="#ffffff", highlightthickness=0)
    giraffe_canvas.grid(row=0, column=0, rowspan=2, padx=(28, 0), pady=(10, 0), sticky="ns")
    giraffe_canvas.create_rectangle(35, 30, 45, 110, fill="#ffeaa7", outline="#fdcb6e", width=2)
    for y in range(40, 110, 18):
        giraffe_canvas.create_oval(37, y, 43, y+10, fill="#fdcb6e", outline="#fdcb6e")
    giraffe_canvas.create_oval(25, 10, 55, 40, fill="#ffeaa7", outline="#fdcb6e", width=2)
    giraffe_canvas.create_oval(22, 8, 30, 18, fill="#ffeaa7", outline="#fdcb6e", width=1)
    giraffe_canvas.create_oval(50, 8, 58, 18, fill="#fdcb6e", outline="#fdcb6e", width=1)
    giraffe_canvas.create_line(32, 10, 28, 2, fill="#fdcb6e", width=3)
    giraffe_canvas.create_line(48, 10, 52, 2, fill="#fdcb6e", width=3)
    giraffe_canvas.create_oval(26, 0, 30, 4, fill="#fdcb6e", outline="#fdcb6e")
    giraffe_canvas.create_oval(50, 0, 54, 4, fill="#fdcb6e", outline="#fdcb6e")
    giraffe_canvas.create_oval(35, 22, 39, 26, fill="#636e72", outline="")
    giraffe_canvas.create_oval(41, 22, 45, 26, fill="#636e72", outline="")
    # 文件扩展名输入框
    ext_frame = tk.Frame(card, bg="#ffffff")
    ext_frame.grid(row=0, column=1, columnspan=3, padx=(0, 0), pady=(18, 0), sticky="w")
    ext_canvas = tk.Canvas(ext_frame, width=20, height=40, bg="#ffffff", highlightthickness=0)
    ext_canvas.pack(side=tk.LEFT, fill=tk.Y)
    ext_canvas.create_rectangle(8, 0, 12, 40, fill="#ffeaa7", outline="#fdcb6e", width=2)
    # 输入框
    extension_entry = tk.Entry(
        ext_frame,
        font=("微软雅黑", 13, "bold"),
        width=22,
        bg="#fffbe6",
        relief="flat",
        highlightthickness=2,
        highlightbackground="#fdcb6e",
        highlightcolor="#fdcb6e",
        borderwidth=0,
        insertbackground="#fdcb6e",
        fg="#636e72"
    )
    extension_entry.pack(side=tk.LEFT, ipady=8, ipadx=2, padx=(0, 0))
    # 标签
    tk.Label(ext_frame, text="文件扩展名", font=("微软雅黑", 13, "bold"), bg="#ffffff", fg="#0984e3").pack(side=tk.LEFT, padx=(12, 0), pady=0)
    recog_btn = tk.Button(card, text="识别扩展名", command=lambda: show_file_select(extension_entry), font=("微软雅黑", 11), bg="#81ecec", fg="#2d3436", width=13, relief="flat", cursor="hand2", activebackground="#b2bec3")
    recog_btn.grid(row=0, column=4, padx=10, pady=18, sticky="w")
    # 应用程序路径输入框
    app_frame = tk.Frame(card, bg="#ffffff")
    app_frame.grid(row=1, column=1, columnspan=3, padx=(0, 0), pady=(0, 0), sticky="w")
    app_canvas = tk.Canvas(app_frame, width=20, height=40, bg="#ffffff", highlightthickness=0)
    app_canvas.pack(side=tk.LEFT, fill=tk.Y)
    app_canvas.create_rectangle(8, 0, 12, 40, fill="#ffeaa7", outline="#fdcb6e", width=2)
    # 输入框
    app_path_entry = tk.Entry(
        app_frame,
        font=("微软雅黑", 13, "bold"),
        width=22,
        bg="#fffbe6",
        relief="flat",
        highlightthickness=2,
        highlightbackground="#fdcb6e",
        highlightcolor="#fdcb6e",
        borderwidth=0,
        insertbackground="#fdcb6e",
        fg="#636e72"
    )
    app_path_entry.pack(side=tk.LEFT, ipady=8, ipadx=2, padx=(0, 0))
    # 标签
    tk.Label(app_frame, text="应用程序路径", font=("微软雅黑", 13, "bold"), bg="#ffffff", fg="#0984e3").pack(side=tk.LEFT, padx=(12, 0), pady=0)
    def browse_app():
        filepath = filedialog.askopenfilename(title="选择应用程序")
        if filepath:
            app_path_entry.delete(0, tk.END)
            app_path_entry.insert(0, filepath)
    browse_btn = tk.Button(card, text="浏览...", command=browse_app, font=("微软雅黑", 11), bg="#00b894", fg="white", width=10, relief="flat", cursor="hand2", activebackground="#00cec9")
    browse_btn.grid(row=1, column=4, padx=10, pady=12, sticky="w")
    # 按钮
    style = ttk.Style()
    style.theme_use("default")
    style.configure("Pro.TButton",
        font=("微软雅黑", 12, "bold"),
        foreground="#273c75",
        background="#f1f2f6",
        borderwidth=0,
        focusthickness=3,
        focuscolor="#81ecec",
        padding=8
    )
    style.map("Pro.TButton",
        background=[("active", "#dff9fb"), ("!active", "#f1f2f6")],
        foreground=[("active", "#0984e3"), ("!active", "#273c75")]
    )
    # 操作按钮区样式
    btn_frame = tb.Frame(card, bootstyle="light")
    btn_frame.grid(row=2, column=0, columnspan=4, pady=(18, 0), sticky="ew")
    btn_style_map = [
        ("保存设置", lambda: save_settings(), "success-outline"),
        ("规则编辑器", lambda: open_rule_editor(), "warning-outline"),
        ("导入规则", import_rules, "secondary-outline"),
        ("导出规则", export_rules, "secondary-outline"),
        ("默认程序设定统计", show_stats, "info-outline"),
        ("更换文件夹图标", show_set_folder_icon_dialog, "primary-outline"),
        ("规则空间", show_rule_community, "success-outline"),
        ("设定目录密码", show_set_folder_password_dialog, "danger-outline"),
        ("取消目录密码", show_remove_folder_password_dialog, "secondary-outline"),
    ]
    btns_per_row = 3
    total_btns = len(btn_style_map)
    rows = (total_btns + btns_per_row - 1) // btns_per_row
    for idx, (text, cmd, style) in enumerate(btn_style_map):
        row = idx // btns_per_row
        col = idx % btns_per_row
        btn = tb.Button(
            btn_frame,
            text=text,
            command=cmd,
            bootstyle=style,
            width=18,
            padding=(8, 6),
        )
        btn.grid(row=row, column=col, padx=18, pady=10, sticky="ew")
    for row in range(rows):
        btn_count_this_row = min(btns_per_row, total_btns - row * btns_per_row)
        empty_left = (btns_per_row - btn_count_this_row) // 2
        for col in range(btns_per_row):
            if col < empty_left or col >= empty_left + btn_count_this_row:
                spacer = tb.Label(btn_frame, text="", bootstyle="light")
                spacer.grid(row=row, column=col, padx=18, pady=10)
    # 底部提示
    tip_frame = tk.Frame(root, bg="#f5f6fa")
    tip_frame.grid(row=4, column=0, columnspan=5, pady=(10, 0), sticky="ew")
    tk.Label(tip_frame, text="如遇WPS反复接管，请关闭WPS相关设置或卸载WPS Office组件。", fg="#d63031", bg="#f5f6fa", font=("微软雅黑", 11)).pack(pady=2)
    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)
    card.grid_columnconfigure(1, weight=1)
    def save_settings():
        extension = extension_entry.get()
        app_path = app_path_entry.get()
        if extension and app_path:
            ext_list = [e.strip() for e in extension.split("/") if e.strip()]
            success_count = 0
            for ext in ext_list:
                if not ext.startswith("."):
                    ext = "." + ext
                try:
                    set_default_app(ext, app_path)
                    rules.append({'ext': ext, 'app': app_path, 'priority': len(rules)+1})
                    if check_default_app(ext, app_path):
                        success_count += 1
                except Exception as e:
                    print(f"设置 {ext} 失败: {e}")
            if success_count == len(ext_list):
                messagebox.showinfo("成功", f"已设置 {', '.join(ext_list)} 的默认程序为: {app_path}")
            elif success_count > 0:
                messagebox.showwarning("部分成功", f"部分扩展名设置成功，部分失败，请检查。")
            else:
                messagebox.showerror("error", f"全部设置失败，请检查输入。")
        else:
            messagebox.showwarning("warning", "请填写完整信息")
    def open_rule_editor():
        editor = RuleEditor(root, rules)
        root.wait_window(editor)
        apply_rules()
    root.mainloop()
def listen_hotkey():
    # 用户如果按下ctrl+p，则会再开一个新窗口
    def on_hotkey():
        threading.Thread(target=create_gui).start()
    keyboard.add_hotkey('ctrl+p', on_hotkey)
    keyboard.wait()
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
def find_executable_in_path(exe_name):
    """在系统PATH和常见目录中查找可执行文件，返回绝对路径或None"""
    # 1. 系统PATH
    for path in os.environ.get("PATH", "").split(os.pathsep):
        exe_path = os.path.join(path, exe_name)
        if os.path.isfile(exe_path):
            return exe_path
    # 2. 常见安装目录
    common_dirs = [
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
        os.environ.get("USERPROFILE", r"C:\Users\Default"),
        r"C:\Windows\System32",
        r"C:\Windows",
    ]
    for base in common_dirs:
        for root, dirs, files in os.walk(base):
            if exe_name.lower() in [f.lower() for f in files]:
                return os.path.join(root, exe_name)
    # 3. 桌面、下载等
    user_dirs = [
        os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
        os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    ]
    for base in user_dirs:
        for root, dirs, files in os.walk(base):
            if exe_name.lower() in [f.lower() for f in files]:
                return os.path.join(root, exe_name)
    return None
def smart_resolve_app_path(app_path):
    """
    根据规则中的app_path，自动在本地查找同名可执行文件，返回本地实际路径或None
    """
    if not app_path or not isinstance(app_path, str):
        return None
    exe_name = os.path.basename(app_path)
    # 先判断原路径是否存在
    if os.path.isfile(app_path):
        return app_path
    # 再查找同名exe
    found = find_executable_in_path(exe_name)
    return found
def apply_rules_with_smart_path(rules_json):
    """
    只应用本地能找到程序的规则，自动替换为本地实际路径
    """
    applied_count = 0
    for rule in sorted(rules_json, key=lambda x: x.get('priority', 0)):
        ext = rule.get('ext')
        app = rule.get('app')
        if not ext or not app:
            continue
        local_app = smart_resolve_app_path(app)
        if local_app:
            set_default_app(ext, local_app)
            rules.append({'ext': ext, 'app': local_app, 'priority': len(rules)+1})
            applied_count += 1
    return applied_count
if __name__ == "__main__":
    if is_admin():
        threading.Thread(target=listen_hotkey, daemon=True).start()
        create_gui()
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "\"" + __file__ + "\"", None, 1)
        sys.exit()