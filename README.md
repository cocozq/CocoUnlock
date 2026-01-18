# CocoUnlock

一个独立的 Windows 命令行工具：输入文件或文件夹路径，列举占用进程，并可选择结束进程以解除占用。

## 用法

- `CocoUnlock.exe <文件或文件夹路径>`  
  列出占用进程后，默认会提示确认，确认后结束进程解除占用
- `CocoUnlock.exe <路径> --list` 或 `-l`  
  仅列举占用进程，不解除
- `CocoUnlock.exe <路径> --yes` 或 `-y`  
  不经过确认直接结束进程

## 构建

打开 `CocoUnlock.sln`，选择 `Release|x64` 生成。

