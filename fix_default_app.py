import winreg
import tkinter as tk
from tkinter import filedialog, messagebox
import ctypes
import sys

def set_default_app(file_extension, app_path):
    """
    设置指定文件扩展名的默认打开程序
    :param file_extension: 文件扩展名，如'.txt'
    :param app_path: 应用程序完整路径
    """
    try:
        # 打开注册表键
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, file_extension) as key:
            # 获取或创建ProgID
            prog_id = winreg.QueryValue(key, None)
            if not prog_id:
                prog_id = file_extension[1:].upper() + "File"
                winreg.SetValue(key, None, winreg.REG_SZ, prog_id)
            
            # 设置ProgID的默认打开命令
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, f"{prog_id}\shell\open\command") as cmd_key:
                winreg.SetValue(cmd_key, None, winreg.REG_SZ, f"\"{app_path}\" \"%1\"")
                
        # 处理Windows 10/11特有的UserChoice键
        user_choice_path = f"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\{file_extension}\\"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, user_choice_path, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.DeleteKey(key, "UserChoice")
        except WindowsError:
            pass
            
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, user_choice_path + "UserChoice") as key:
            winreg.SetValueEx(key, "ProgId", 0, winreg.REG_SZ, prog_id)
            winreg.SetValueEx(key, "Hash", 0, winreg.REG_SZ, "")
                
        print(f"成功设置 {file_extension} 的默认打开程序为: {app_path}")
    except Exception as e:
        print(f"设置默认程序失败: {e}")

def create_gui():
    root = tk.Tk()
    root.title("设置默认程序")
    
    # 文件扩展名输入
    tk.Label(root, text="文件扩展名(如 .txt):").grid(row=0, column=0, padx=5, pady=5)
    extension_entry = tk.Entry(root)
    extension_entry.grid(row=0, column=1, padx=5, pady=5)
    
    # 应用程序路径选择
    tk.Label(root, text="应用程序路径:").grid(row=1, column=0, padx=5, pady=5)
    app_path_entry = tk.Entry(root)
    app_path_entry.grid(row=1, column=1, padx=5, pady=5)
    
    def browse_app():
        filepath = filedialog.askopenfilename(title="选择应用程序")
        if filepath:
            app_path_entry.delete(0, tk.END)
            app_path_entry.insert(0, filepath)
    
    tk.Button(root, text="浏览...", command=browse_app).grid(row=1, column=2, padx=5, pady=5)
    
    # 保存按钮
    def save_settings():
        extension = extension_entry.get()
        app_path = app_path_entry.get()
        if extension and app_path:
            try:
                set_default_app(extension, app_path)
                messagebox.showinfo("成功", f"已设置 {extension} 的默认程序为: {app_path}")
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
        # 重新以管理员权限运行
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, "\"" + __file__ + "\"", None, 1)
        sys.exit()