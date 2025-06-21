```
                                     ______
                          ____,-----'      (
                         )'                \
                        |                   |
                        |                   |
                       |                     |
                       |+++++++++++++++++++++|
                      |++++++++++++++++++++++ |_
                  __,-|+++++++++;"""""""""""""  `--._
           ___,--'     ~~~~~~~~~    _______________ _`-.
         ,'          ________,-----'~~~~~~~~~~~~~~######-.
         `---._____,-'~~~~~~~                __     ~~~~~~
              ~~~~~       ____      ____,---' \\
                         /::::\    /::::\      ||
                        |::::::|==|::::::|
                         \::::/    \:::::/
                          ~~~~      ~~~~~
'##::::'##::'#######::'##:::::::'##::::::::'#######::'##:::::'##::::'##::::'##::::'###::::'##::: ##:
 ##:::: ##:'##.... ##: ##::::::: ##:::::::'##.... ##: ##:'##: ##:::: ###::'###:::'## ##::: ###:: ##:
 ##:::: ##: ##:::: ##: ##::::::: ##::::::: ##:::: ##: ##: ##: ##:::: ####'####::'##:. ##:: ####: ##:
 #########: ##:::: ##: ##::::::: ##::::::: ##:::: ##: ##: ##: ##:::: ## ### ##:'##:::. ##: ## ## ##:
 ##.... ##: ##:::: ##: ##::::::: ##::::::: ##:::: ##: ##: ##: ##:::: ##. #: ##: #########: ##. ####:
 ##:::: ##: ##:::: ##: ##::::::: ##::::::: ##:::: ##: ##: ##: ##:::: ##:.:: ##: ##.... ##: ##:. ###:
 ##:::: ##:. #######:: ########: ########:. #######::. ###. ###::::: ##:::: ##: ##:::: ##: ##::. ##:
..:::::..:::.......:::........::........:::.......::::...::...::::::..:::::..::..:::::..::..::::..::
```                                                                                    
                                 Process Hollowing in C++ (x86 / x64)         
                                    Process PE Image Replacement
                                 Original Author: https://github.com/adamhlt/Process-Hollowing
<p align="center">
  <img src="https://img.shields.io/badge/language-C%2B%2B-%23f34b7d.svg?style=for-the-badge&logo=appveyor" alt="C++">
  <img src="https://img.shields.io/badge/platform-Windows-0078d7.svg?style=for-the-badge&logo=appveyor" alt="Windows">
  <img src="https://img.shields.io/badge/arch-x64-green.svg?style=for-the-badge&logo=appveyor" alt="x64">
</p>

# Hollowman

## 🆕 What's New
- **Interactive I/O support**: stdin/stdout of the hollowed process is now redirected back to your host console (e.g. `cmd.exe`) so you can type commands and see live output.

## 📖 Project Overview
Hollowman is a **x64** process-hollowing loader written in C++, forked from adamhlt's Process Hollowing repository. It can inject a PE image (x86 or x64) into either an x86 or x64 target process by performing:

- PE signature validation  
- Architecture compatibility check (x86↔x86 or x64↔x64)  
- Subsystem compatibility check (console vs GUI)  
- Relocation table handling (if present)  

If the payload has no relocation table, Hollowman will allocate memory at the payload’s preferred image base. For a deep dive into PE internals, see the [PE-Explorer project](https://github.com/adamhlt/PE-Explorer).

## 🚀 Getting Started

> **Warning**  
> This is a **x64** executable. You cannot build or run it as x86. It is designed to inject into both x86 and x64 processes only.

### Visual Studio

1. Open `Hollowman.sln` in Visual Studio.  
2. Set the configuration to **Release** and the platform to **x64**.  
3. Build the solution.

### CMake (other IDEs)

\`\`\`cmake
cmake_minimum_required(VERSION 3.0)
project(Hollowman)

set(CMAKE_CXX_STANDARD 17)
add_executable(Hollowman ProcessHollowing.cpp)
\`\`\`

Tested on CLion with the MSVC toolchain. You can install the Build Tools for Visual Studio from the [official Microsoft download page](https://visualstudio.microsoft.com/downloads/#other).

## 🧪 Usage

\`\`\`shell
Hollowman.exe <source image> <target process>
\`\`\`

- **\`<source image>\`**: full path to the PE you want to inject (e.g. \`C:\Payloads\MyApp.exe\`)  
- **\`<target process>\`**: command-line of the host to hollow (e.g. \`C:\Windows\System32\cmd.exe\`)  

Example:

\`\`\`shell
Hollowman.exe C:\Payloads\HiWorld.exe C:\Windows\System32\cmd.exe
\`\`\`

![image](https://github.com/user-attachments/assets/44168fed-7b70-44de-87c2-da7c76ff69ea)

## 🔗 License

Distributed under the MIT License. See \`LICENSE\` for details.
