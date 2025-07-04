<p align="left">
<img src="image3.png" alt="File Default Master" style="width:50px; height:auto; vertical-align:middle;border-radius:50%;">
<span style="font-size:2em;vertical-align:top;"><b>文件默认大师</b></span>
</p>


<p align="right">
  <a href="README_en.md" style="font-size:18px;text-decoration:none;">English</a> | <b>中文</b>
</p>

![alt text](image.png)
这是一个Windows工具，用于设置文件扩展名的默认打开程序。大家可能经常会遇到用windows指定默认的应用程序打开某种文件扩展名（比如.html用Edge打开，而不想用联想浏览器打开），但是经常的情况是改了以后当时有用，重启后就没有效果了。于是我开发了这样的工具fix_default_app.exe来快速的让大家选择某个文件扩展名需要打开的默认应用程序，并且电脑重启后仍有效。

---

## 主要功能概述

文件默认大师是一款面向Windows平台的文件扩展名默认程序设置与管理工具，具备以下主要功能：

- **批量设置默认程序**  
  支持一次输入多个扩展名，统一设置默认打开程序，极大提升文件关联效率。

- **规则管理与优先级排序**  
  内置图形化拖拽式规则编辑器，支持添加、编辑、删除、排序所有文件关联规则，灵活管理不同扩展名的默认打开方式。

- **规则导入导出**  
  支持将所有自定义规则导出为JSON文件，便于备份、迁移、分享，也可一键导入规则文件，快速恢复设置。

- **默认程序设定统计与搜索**  
  自动扫描系统所有扩展名及其当前默认程序，并以表格展示，支持模糊搜索扩展名或程序路径，方便定位和检查关联情况。
![image](https://github.com/user-attachments/assets/3626c3fa-2750-47c3-ab4a-5b8bdb958981)

- **全局快捷键唤起**  
  支持按下Ctrl+P快捷键，随时唤起主界面，便于快速操作和管理。

- **规则空间（网络功能）**  
  用户可注册、登录、上传本地规则到“规则空间”，浏览、下载、评分、举报他人分享的规则，支持标签筛选和关键词搜索，实现规则的云端共享与交流。
 ![image](https://github.com/user-attachments/assets/09e7ea00-a530-4b58-ba1d-10a0f5b960aa)


- **文件夹图标更换**  
  支持自定义文件夹图标，自动将图片转换为ico并设置，提升文件夹辨识度和个性化。

- **目录加密/解密**  
  支持对文件夹设置密码，隐藏和保护文件夹内容，输入密码后可恢复，保障数据安全。

- **兼容性与易用性**  
  结合Windows命令行和注册表双重设置，兼容Windows 10/11，界面简洁直观，操作便捷，适合所有用户。

## 技术特点

- 跨平台易维护，我用tkinter和ttkbootstrap实现现代化图形界面。
- 结合Windows命令行与注册表双重机制，确保文件关联设置的兼容性和持久性。
- 支持批量处理、多规则优先级排序，规则以结构化JSON格式存储，便于导入导出和团队协作。
- 规则空间采用Flask RESTful API服务端，所有数据持久化为JSON文件，支持多用户、评分、标签、举报等功能。
- 文件夹图标更换模块支持多种图片格式自动转换ico，desktop.ini自动生成，兼容Windows资源管理器。
- 目录加密功能采用SHA256哈希保护密码，内容隐藏于特殊子目录，保障数据安全。
- 全局快捷键监听，支持后台随时唤起主界面。
- 代码结构清晰，模块解耦，便于扩展和二次开发。
- 兼容Windows 10/11，支持管理员权限自动提升，适配主流办公环境。

**文件默认大师** —— 让你的Windows文件关联管理更高效、更智能、更专业！

## 使用方法
1. 运行`fix_default_app.py`
2. 输入文件扩展名(如 `.txt` 或 `.doc/.docx`)
3. 选择应用程序路径（指定的默认应用程序路径可以是应用程序的真实路径或者快捷方式，路径的结尾是：.exe）
4. 点击"保存设置"按钮
5. 可使用“规则编辑器”管理所有关联规则，或导入/导出规则文件
6. 点击“默认程序设定统计”可查看和搜索系统所有扩展名的默认程序
7. 如果你喜欢，请给仓库一个star

## 依赖
- Python 3.8+
- tkinter
- pyinstaller(打包)
- keyboard
- requests  

## 常见问题解答

### Q: 规则空间中下载/应用他人规则时，默认程序路径和我本地安装路径不同怎么办？

A:  
文件默认大师的规则空间支持自动识别和替换本地程序路径。当你下载并应用他人分享的规则时，软件会自动扫描你本地系统，查找规则中指定的应用程序（如`notepad.exe`、`wps.exe`等）在你电脑上的实际安装位置。如果本地找到了同名程序，则自动替换为你本地的路径并应用规则。如果本地没有找到该程序，则这条规则不会被应用，只有能在你本地系统扫描到相应应用程序的规则才会生效。

**注意事项：**
- 自动查找会遍历系统PATH、常见安装目录（如`C:\Program Files`、`C:\Windows\System32`等）、用户桌面和下载目录等，最大程度兼容不同用户的安装环境。
- 如果你本地没有安装某个程序，则对应的规则不会生效。
- 建议应用规则后，在“规则编辑器”中检查每条规则的应用程序路径，确保路径正确。
- 上传规则时建议在描述中注明所用程序的名称和版本，方便他人查找和匹配。

### Q: 文件默认大师是如何解决规则空间中不同用户同一程序安装路径不一致的问题？

A:  
文件默认大师在“规则空间”下载和应用他人规则时，会自动扫描本地系统，查找规则中指定的应用程序（如`notepad.exe`、`wps.exe`等）在你电脑上的实际安装位置。具体实现方式：

应用规则时，软件会提取规则中每条规则的app字段（即应用程序路径），获取可执行文件名。
首先判断规则中的原始路径在本地是否存在，如果存在则直接使用。
如果原始路径不存在，则自动在本地系统的PATH环境变量、常见安装目录、用户桌面、下载目录等位置查找同名可执行文件。
如果找到同名程序，则自动替换为本地实际路径并应用该规则；如果找不到，则该条规则不会被应用。
这样可以最大程度兼容不同用户的安装环境，实现“规则共享但路径本地化”。

**总结：**  
你无需手动修改路径，文件默认大师会自动帮你“智能匹配”本地可用的程序路径，只应用本地能找到的规则，保证规则空间的跨用户兼容性和易用性。

**举例：**  
- 规则空间规则中的路径是 `C:\Program Files\A.exe`，你本地实际安装在 `D:\MyApps\A.exe`，只要文件名都是 `A.exe`，就会自动匹配并应用。
- 如果你本地没有 `A.exe`，则该条规则不会被应用。

注意：  
由于Windows 的安全策略限制，所以.pdf 需在系统设置中手动指定默认程序。无法完全自动化
