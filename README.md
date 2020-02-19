# ExFunc
通达信PC版本的函数DLL封装

使用非对称加密，最终用户只能拿到公钥和license 文件，在验证失败的情况下，不能够使用dll中的函数。
用户的license是根据用户的windows用户名和机器的cpu id生成的，用户换了机器和用户后，需要重新授权。
授权方的私钥一定要妥善保存。

授权和使用流程
1.	用户拿到软件后,首先生成token文件.

用户拿到的文件有:
1)	公式的dll(ExFuncPlugin.dll),放置到 通达信的安装目录下的子目录T0002\dlls下
2)	公钥文件 pubkey.pem ,放置到c:/exfunc目录下
3）ExFunc.exe token/license生成工具
2.	用户生成token文件发给授权方,

1)	使用exfunc程序，选择1 ，生成token文件保存在c:/exfunc/目录下。
 
2)	token文件保存到c:/exfunc/token
3)	将token文件发送给授权方

3.	授权方生成license文件.
	授权方的c:/exfunc/目录下要有公钥pubkey.pem和私钥文件prikey.pem，缺一不可。
	授权方将用户提交的token文件拷贝到c:/exfunc目录下，运行Exfunc.exe,选择2，生成license 文件，license 文件保存在c:/exfunc/目录下。
	授权方还可以选择3进行验证。
	授权方将license文件提交给用户。
4.	用户将license文件放置到固定位置c:/exfunc目录下,对应的dll库才能正常使用.
注意，用户登录windows的用户名，必须和生成token时的一致，否则也不可以使用。
5.	用户还需要在证券软件中倒入dll，然后定义自己的函数
比如:
 


 
这里，定义了一个绘制红色曲线的函数SDFS，
TDXDLL1 代表是调用DLL1，
(2,H,L,C)  是DLL1的第二个函数，H，L，C是这个函数带的三个参数，对应的是内置的K线的开盘、最低、收盘 价格，除第一个参数外，其他的参数个数和参数值可以任意修改。但是要和DLL里的函数定义对应起来，比如这个函数的定义就是：
 

这里的后面三个参数就对应pfINa，pfINb,pfINc,，因为曲线是一系列的数据组成，所以这三个参数都是数组，而且长度是一致的，都是datalen,返回的曲线y轴坐标就是pfOUT.(x轴是时间)。

需要定制的选股函数，要集成到DLL代码中。
股票软件中的函数定义（比如上面的SDFS函数），可以使用倒入到出的方法，减少用户的配置难度。







