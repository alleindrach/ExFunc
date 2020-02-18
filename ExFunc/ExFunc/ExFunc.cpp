// ExFunc.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "Funcs.h"

int main()
{


	while (true) {


		cout << "\n\n选择操作:\n1 生成Token\n2 生成License\n3 验证License\n  " << endl;
		int op;
		cin >> op;

		switch (op) {
		case 1:
		{
			bool success = genToken(tokenFilename, logFilename);
			if (success) {
				cout << "\n生成"<< tokenFilename<<" ！";
			}
			else
			{
				cout << "\n失败！";
			}
		}

		break;
		case 2: {
			bool success = genLicnese(tokenFilename, licenseFilename, logFilename);
			if (success) {
				cout << "\n生成"<< licenseFilename <<" ！";
			}
			else
			{
				cout << "\n失败！";
			}
		}

				break;

		case 3: {
			bool success = verifyLicense(licenseFilename,logFilename);
			if (success) {
				cout << "\n验证成功！";
			}
			else
			{
				cout << "\n验证失败！";
			}
		}

				break;
		}
	}

    return 0;
}

