' itinfra7 on GitHub
Option Explicit

Dim shellApp
Dim fileSystem
Dim shell
Dim ps1Path
Dim verb
Dim workingDir
Dim logPath
Dim scriptStem
Dim argLine
Dim i

If WScript.Arguments.Count < 2 Then
    WScript.Quit 1
End If

Set shellApp = CreateObject("Shell.Application")
Set fileSystem = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

ps1Path = WScript.Arguments.Item(0)
verb = WScript.Arguments.Item(1)
workingDir = fileSystem.GetParentFolderName(ps1Path)
scriptStem = fileSystem.GetBaseName(ps1Path)
logPath = fileSystem.BuildPath(workingDir, scriptStem & ".launch.log")
argLine = "-NoLogo -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File " & Quote(ps1Path)

For i = 2 To WScript.Arguments.Count - 1
    argLine = argLine & " " & Quote(WScript.Arguments.Item(i))
Next

WriteLog logPath, Array( _
    "Timestamp: " & Now, _
    "Verb: " & verb, _
    "WorkingDirectory: " & workingDir, _
    "PowerShell: powershell.exe", _
    "Arguments: " & argLine _
)

On Error Resume Next
shellApp.ShellExecute "powershell.exe", argLine, workingDir, verb, 0
If Err.Number <> 0 Then
    WriteLog logPath, Array( _
        "Timestamp: " & Now, _
        "LauncherError: " & Err.Description _
    )
    shell.Popup "런처 실행 실패: " & Err.Description & vbCrLf & "로그: " & logPath, 0, "Windows Security Workbench 2016", 16
End If
On Error GoTo 0

Function Quote(value)
    Quote = Chr(34) & Replace(value, Chr(34), Chr(34) & Chr(34)) & Chr(34)
End Function

Sub WriteLog(path, lines)
    Dim stream
    Dim index
    Set stream = fileSystem.OpenTextFile(path, 2, True, 0)
    For index = 0 To UBound(lines)
        stream.WriteLine lines(index)
    Next
    stream.Close
End Sub
