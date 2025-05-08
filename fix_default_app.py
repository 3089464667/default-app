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
from collections import Counter
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

def set_default_app(file_extension, app_path):
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
        import hashlib
        import time
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
    """
    检查当前扩展名的默认打开程序是否为 app_path
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
        self.listbox.delete(0, tk.END)
        for idx, rule in enumerate(self.rules):
            self.listbox.insert(tk.END, f"{idx+1}. {rule['ext']} → {rule['app']} (优先级:{rule['priority']})")
    def add_rule(self):
        ext = simpledialog.askstring("扩展名", "请输入文件扩展名（如 .txt）", parent=self)
        app = filedialog.askopenfilename(title="选择应用程序")
        if ext and app:
            self.rules.append({'ext': ext, 'app': app, 'priority': len(self.rules)+1})
            self.refresh_list()
    def edit_rule(self):
        idx = self.listbox.curselection()
        if not idx:
            return
        idx = idx[0]
        rule = self.rules[idx]
        ext = simpledialog.askstring("扩展名", "修改扩展名", initialvalue=rule['ext'], parent=self)
        app = filedialog.askopenfilename(title="选择应用程序")
        if ext and app:
            self.rules[idx] = {'ext': ext, 'app': app, 'priority': rule['priority']}
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
        self.listbox.select_set(i+1)
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

def create_gui():
    root = tk.Tk()
    root.title("文件默认大师")
    root.geometry("600x350")
    root.configure(bg="#f5f6fa")
    title_label = tk.Label(root, text="文件默认大师", font=("微软雅黑", 20, "bold"), fg="#273c75", bg="#f5f6fa")
    title_label.grid(row=0, column=0, columnspan=3, pady=(18, 8))
    tk.Label(root, text="文件扩展名(如 .txt 或 .doc/.docx):", font=("微软雅黑", 12), bg="#f5f6fa").grid(row=1, column=0, padx=10, pady=8, sticky="e")
    extension_entry = tk.Entry(root, font=("微软雅黑", 12), width=22)
    extension_entry.grid(row=1, column=1, padx=5, pady=8, sticky="w")
    tk.Label(root, text="应用程序路径:", font=("微软雅黑", 12), bg="#f5f6fa").grid(row=2, column=0, padx=10, pady=8, sticky="e")
    app_path_entry = tk.Entry(root, font=("微软雅黑", 12), width=22)
    app_path_entry.grid(row=2, column=1, padx=5, pady=8, sticky="w")
    def browse_app():
        filepath = filedialog.askopenfilename(title="选择应用程序")
        if filepath:
            app_path_entry.delete(0, tk.END)
            app_path_entry.insert(0, filepath)
    browse_btn = tk.Button(root, text="浏览...", command=browse_app, font=("微软雅黑", 11), bg="#00b894", fg="white", width=10, relief="flat", cursor="hand2", activebackground="#00cec9")
    browse_btn.grid(row=2, column=2, padx=10, pady=8)
    def save_settings():
        extension = extension_entry.get()
        app_path = app_path_entry.get()
        if extension and app_path:
            # 支持批量扩展名
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
    save_btn = tk.Button(root, text="保存设置", command=save_settings, font=("微软雅黑", 12, "bold"), bg="#0984e3", fg="white", width=12, relief="flat", cursor="hand2", activebackground="#74b9ff")
    save_btn.grid(row=3, column=1, pady=12)
    def open_rule_editor():
        editor = RuleEditor(root, rules)
        root.wait_window(editor)
        apply_rules()
    rule_btn = tk.Button(root, text="规则编辑器", command=open_rule_editor, font=("微软雅黑", 11), bg="#fdcb6e", fg="#2d3436", width=12, relief="flat", cursor="hand2", activebackground="#ffeaa7")
    rule_btn.grid(row=3, column=2, pady=12)
    import_btn = tk.Button(root, text="导入规则", command=import_rules, font=("微软雅黑", 11), bg="#636e72", fg="white", width=12, relief="flat", cursor="hand2", activebackground="#b2bec3")
    import_btn.grid(row=4, column=0, pady=8)
    export_btn = tk.Button(root, text="导出规则", command=export_rules, font=("微软雅黑", 11), bg="#636e72", fg="white", width=12, relief="flat", cursor="hand2", activebackground="#b2bec3")
    export_btn.grid(row=4, column=1, pady=8)
    stats_btn = tk.Button(root, text="默认程序设定统计", command=show_stats, font=("微软雅黑", 11), bg="#6c5ce7", fg="white", width=16, relief="flat", cursor="hand2", activebackground="#a29bfe")
    stats_btn.grid(row=4, column=2, pady=8)
    tk.Label(root, text="如遇WPS反复接管，请关闭WPS相关设置或卸载WPS Office组件。", fg="#d63031", bg="#f5f6fa", font=("微软雅黑", 10)).grid(row=5, column=0, columnspan=3, pady=10)
    root.mainloop()
def listen_hotkey():
    def on_hotkey():
        threading.Thread(target=create_gui).start()
    keyboard.add_hotkey('ctrl+p', on_hotkey)
    keyboard.wait()
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
if __name__ == "__main__":
    if is_admin():
        threading.Thread(target=listen_hotkey, daemon=True).start()
        create_gui()
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "\"" + __file__ + "\"", None, 1)
        sys.exit()