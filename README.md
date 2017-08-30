# Putty-cn
Putty 中文版,汉化 (Windows)  
## 版本 v0.69.1053.0
PuTTY

Development snapshot 2017-06-16.892d4a0

Build platform: xx-bit Windows

Source commit: 892d4a0188ffd8aa60dc11b4bace30dfb0f9d50e

?1997-2017 Simon Tatham. All rights reserved.

汉化by: lzpong www.cnblogs.com/lzpong/

[更改]
1. 滚轮翻页1/2屏太快了,改成了滚动1/3屏  
  window.c:3323


2. 快捷键清空界面和滚动文档:   (**未实现**,未找到在哪儿加入快捷键)  
  快捷键: Ctrl+M  
  函数:  
```c
void term_clean(){
    term_clrsb(term);
    term_pwron(term, TRUE);
    if (ldisc)
        ldisc_echoedit_update(ldisc);
}
```

## [说明](https://github.com/lzpong/Putty-cn/blob/master/windows/VS2015/%E4%BF%AE%E6%94%B9.txt)
1. 文档滚动函数:  
  terminal.c:5388  term_scroll

2. 清除滚动文档  
  window.c:2431  term_clrsb

3. 清除界面文档  
  window.c:2434  term_pwron

4. 设置配置窗口配置的函数:  
  config.c:1340  setup_config_box  
  windows\wincfg.c:43  win_setup_config_box

5. 界面相关:  
  windows\windlg.c

6. 窗口资源:  
  windows\win_res.rc2  而不是 putty.rc  
  直接在VS资源管理器中修改,会保存为putty.rc,**编译报错** (需要添加#include <winresrc.h>/<windows.h> )

7. 部分默认配置参数:  
  windows\windefs.c
