import winreg
import tkinter as tk
from tkinter import filedialog, messagebox
import ctypes
import sys
import subprocess
import os

def set_default_app_cmd(file_extension, app_path):
    """
    使用 Windows 命令行工具设置默认打开程序，兼容 Windows 10/11
    """
    try:
        ext = file_extension if file_extension.startswith('.') else '.' + file_extension
        prog_id = ext[1:].upper() + "File"
        # 1. 关联扩展名到 ProgID
        subprocess.run(f'assoc {ext}={prog_id}', shell=True, check=True)
        # 2. 设置 ProgID 的打开命令
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
        print(f"命令行设置失败: {msg}")
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
        user_sid = ctypes.windll.advapi32.GetUserNameExW(ctypes.c_int(1), None, ctypes.pointer(ctypes.c_ulong(0)))
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

def create_gui():
    root = tk.Tk()
    root.title("设置默认程序")
    tk.Label(root, text="文件扩展名(如 .txt):").grid(row=0, column=0, padx=5, pady=5)
    extension_entry = tk.Entry(root)
    extension_entry.grid(row=0, column=1, padx=5, pady=5)
    tk.Label(root, text="应用程序路径:").grid(row=1, column=0, padx=5, pady=5)
    app_path_entry = tk.Entry(root)
    app_path_entry.grid(row=1, column=1, padx=5, pady=5)
    def browse_app():
        filepath = filedialog.askopenfilename(title="选择应用程序")
        if filepath:
            app_path_entry.delete(0, tk.END)
            app_path_entry.insert(0, filepath)
    tk.Button(root, text="浏览...", command=browse_app).grid(row=1, column=2, padx=5, pady=5)
    def save_settings():
        extension = extension_entry.get()
        app_path = app_path_entry.get()
        if extension and app_path:
            try:
                set_default_app(extension, app_path)
                if check_default_app(extension, app_path):
                    messagebox.showinfo("成功", f"已设置 {extension} 的默认程序为: {app_path}")
                else:
                    messagebox.showwarning("注意", f"设置已尝试，但系统可能未生效，请重启电脑或手动在“默认应用”中检查。")
            except Exception as e:
                messagebox.showerror("错误", f"设置失败: {e}")
        else:
            messagebox.showwarning("警告", "请填写完整信息")
    tk.Button(root, text="保存设置", command=save_settings).grid(row=2, column=1, pady=10)
    root.mainloop()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    if is_admin():
        create_gui()
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "\"" + __file__ + "\"", None, 1)
        sys.exit()