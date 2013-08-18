========================================================================
    CONSOLE APPLICATION : procclone Project Overview
========================================================================

Sometimes, you need to impersonate some processes to do something, such as,
You want to see if a process has permission or privilege to do something, 
you need to steal its security token and use the token to do something you want.

procclone helps you.

run proclone as "procclone <pid|pname> cmd.exe" it will create a command prompt
with the security token that used by specified process and then you can do
whatever you want to do from that command prompt.