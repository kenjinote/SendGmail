#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib,"crypt32")
#pragma comment(lib,"libeay32")
#pragma comment(lib,"ssleay32")
#pragma comment(lib,"ws2_32")
#pragma comment(lib,"shlwapi")

#include<winsock2.h>
#include"openssl/ssl.h"
#include"openssl/rand.h"
#include<shlwapi.h>

#define GMAIL_ACCOUNT "ジーメイルアカウント（メールアドレス）を入力してください。"
#define GMAIL_PASSWORD "ジーメイルパスワードを入力してください。"

CHAR convtobase(const CHAR c)
{
	if (c <= 0x19)return c + 'A';
	if (c >= 0x1a && c <= 0x33)return c - 0x1a + 'a';
	if (c >= 0x34 && c <= 0x3d)return c - 0x34 + '0';
	if (c == 0x3e)return '+';
	if (c == 0x3f)return '/';
	return '=';
}

void encode(LPCSTR lpszOrg, LPSTR lpszDest)
{
	int i = 0, iR = 16;
	lstrcpyA(lpszDest, "=?ISO-2022-JP?B?");
	for (;;)
	{
		if (lpszOrg[i] == '\0')
		{
			break;
		}
		lpszDest[iR] = convtobase((lpszOrg[i]) >> 2);
		if (lpszOrg[i + 1] == '\0')
		{
			lpszDest[iR + 1] = convtobase(((lpszOrg[i] & 0x3) << 4));
			lpszDest[iR + 2] = '=';
			lpszDest[iR + 3] = '=';
			lpszDest[iR + 4] = '\0';
			break;
		}
		lpszDest[iR + 1] = convtobase(((lpszOrg[i] & 0x3) << 4) + ((lpszOrg[i + 1]) >> 4));
		if (lpszOrg[i + 2] == '\0')
		{
			lpszDest[iR + 2] = convtobase((lpszOrg[i + 1] & 0xf) << 2);
			lpszDest[iR + 3] = '=';
			lpszDest[iR + 4] = '\0';
			break;
		}
		lpszDest[iR + 2] = convtobase(((lpszOrg[i + 1] & 0xf) << 2) + ((lpszOrg[i + 2]) >> 6));
		lpszDest[iR + 3] = convtobase(lpszOrg[i + 2] & 0x3f);
		lpszDest[iR + 4] = '\0';
		i += 3;
		iR += 4;
	}
	lstrcatA(lpszDest, "?=");
	return;
}

LPSTR MySJisToJis(LPCSTR lpszOrg)
{
	LPSTR MultiString = 0;
	DWORD dwTextLen = MultiByteToWideChar(932, 0, lpszOrg, -1, 0, 0);
	if (dwTextLen)
	{
		LPWSTR WideString = (LPWSTR)GlobalAlloc(GMEM_FIXED, sizeof(WCHAR)*(dwTextLen + 1));
		MultiByteToWideChar(932, 0, lpszOrg, -1, WideString, dwTextLen);
		dwTextLen = WideCharToMultiByte(50220, 0, WideString, -1, 0, 0, 0, 0);
		if (dwTextLen)
		{
			MultiString = (LPSTR)GlobalAlloc(GMEM_FIXED, sizeof(CHAR)*(dwTextLen + 1));
			WideCharToMultiByte(50220, 0, WideString, -1, MultiString, dwTextLen, 0, 0);
		}
		GlobalFree(WideString);
	}
	return MultiString;
}

LPSTR base64encode(LPBYTE lpData, DWORD dwSize)
{
	DWORD dwResult = 0;
	if (CryptBinaryToStringA(lpData, dwSize, CRYPT_STRING_BASE64, 0, &dwResult))
	{
		LPSTR lpszBase64 = (LPSTR)GlobalAlloc(GMEM_FIXED, dwResult);
		if (CryptBinaryToStringA(lpData, dwSize, CRYPT_STRING_BASE64, lpszBase64, &dwResult))
		{
			*(LPWORD)(lpszBase64 + dwResult - 2) = 0;
			return lpszBase64;
		}
	}
	return 0;
}

BOOL SendMail(
	LPSTR lpszToAddress2,
	LPCSTR lpszFromAddress2,
	LPCSTR lpszSubject2,
	LPSTR lpszMessage2,
	LPSTR*lpszAttachment2,
	const DWORD dwAttachmentCount,
	const BOOL bLog
	)
{
	BOOL bRet = TRUE;

	DWORD dwWritten;

	WSADATA wsaData;
	LPHOSTENT lpHost;
	SOCKET s;
	SOCKADDR_IN sockadd;
	LPSTR token;

	LPSTR lpszText;
	DWORD dwTextLength;

	DWORD i;

	CHAR szStr[1024], szStrRcv[1024 * 50];//ここの制限もなくしたい

	if (WSAStartup(MAKEWORD(1, 1), &wsaData))
	{
		lstrcpyA(szStrRcv, "エラー: WinSockの初期化に失敗しました。\r\n");
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
		bRet = FALSE;
		goto END0;
	}

	LPSTR*lpszBase64Code;
	lpszBase64Code = (LPSTR*)GlobalAlloc(GMEM_ZEROINIT, sizeof(LPSTR)*dwAttachmentCount);
	if (lpszBase64Code == 0)
	{
		lstrcpyA(szStrRcv, "エラー: 添付の初期化に失敗しました。\r\n");
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
		bRet = FALSE;
		goto END1;
	}
	for (i = 0; i<dwAttachmentCount; i++)
	{
		HANDLE hFile1; hFile1 = CreateFileA(lpszAttachment2[i], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hFile1 == INVALID_HANDLE_VALUE)
		{
			wsprintfA(szStrRcv, "エラー: 添付ファイルが開けませんでした。[%s]\r\n", PathFindFileNameA(lpszAttachment2[i]));
			WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
			bRet = FALSE;
			goto END2;
		}
		LARGE_INTEGER FileSize;
		SecureZeroMemory(&FileSize, sizeof(FileSize));
		if (!GetFileSizeEx(hFile1, &FileSize))
		{
			CloseHandle(hFile1);
			wsprintfA(szStrRcv, "エラー: 添付ファイルサイズを取得できませんでした。[%s]\r\n", PathFindFileNameA(lpszAttachment2[i]));
			WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
			bRet = FALSE;
			goto END2;
		}
		if (FileSize.HighPart || FileSize.LowPart>1024 * 1024 * 25 || FileSize.LowPart == 0)
		{
			CloseHandle(hFile1);
			wsprintfA(szStrRcv, "エラー: 添付ファイルサイズが異常です。[%s]\r\n", PathFindFileNameA(lpszAttachment2[i]));
			WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
			bRet = FALSE;
			goto END2;
		}
		LPBYTE p; p = (LPBYTE)GlobalAlloc(GMEM_FIXED, FileSize.LowPart);
		if (p == NULL)
		{
			CloseHandle(hFile1);
			wsprintfA(szStrRcv, "エラー: 添付ファイルのためのメモリが確保できませんでした。[%s]\r\n", PathFindFileNameA(lpszAttachment2[i]));
			WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
			bRet = FALSE;
			goto END2;
		}
		DWORD end1;
		ReadFile(hFile1, p, FileSize.LowPart, &end1, NULL);
		CloseHandle(hFile1);
		if (end1 == 0)
		{
			GlobalFree(p);
			wsprintfA(szStrRcv, "エラー: 添付ファイルからデータを読み込めませんでした。[%s]\r\n", PathFindFileNameA(lpszAttachment2[i]));
			WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
			bRet = FALSE;
			goto END2;
		}
		lpszBase64Code[i] = base64encode(p, FileSize.LowPart);
		GlobalFree(p);
		if (lpszBase64Code[i] == 0)
		{
			wsprintfA(szStrRcv, "エラー: 添付ファイルのBase64エンコードに失敗しました。[%s]\r\n", PathFindFileNameA(lpszAttachment2[i]));
			WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
			bRet = FALSE;
			goto END2;
		}
	}

	lpHost = gethostbyname("smtp.gmail.com");
	if (lpHost == 0)
	{
		wsprintfA(szStrRcv, "エラー: メールサーバーが見つかりませんでした。[%s]\r\n", "smtp.gmail.com");
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
		bRet = FALSE;
		goto END2;
	}
	s = socket(PF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
	{
		lstrcpyA(szStrRcv, "エラー: ソケットをオープンできませんでした。\r\n");
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
		bRet = FALSE;
		goto END2;
	}
	sockadd.sin_family = AF_INET;
	sockadd.sin_port = htons(465);
	sockadd.sin_addr = *((LPIN_ADDR)*lpHost->h_addr_list);
	if (connect(s, (PSOCKADDR)&sockadd, sizeof(sockadd)))
	{
		lstrcpyA(szStrRcv, "エラー: サーバーソケットに接続に失敗しました。\r\n");
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
		bRet = FALSE;
		goto END3;
	}

	SSLeay_add_ssl_algorithms();
	SSL_load_error_strings();
	SSL_library_init();
	char qrandomstring[15];
	srand((unsigned int)time(0));
	wsprintfA(qrandomstring, "%d", rand());
	RAND_seed(qrandomstring, strlen(qrandomstring));
	SSL_CTX *ctx; ctx = SSL_CTX_new(SSLv23_client_method());
	SSL *ssl; ssl = SSL_new(ctx);
	SSL_set_fd(ssl, s);
	if (SSL_connect(ssl) <= 0)
	{
		lstrcpyA(szStrRcv, "エラー: SSLの初期化に失敗しました。\r\n");
		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0);
		bRet = FALSE;
		goto END4;
	}

	int err;

	lstrcpyA(szStr, "EHLO\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

	memset(szStrRcv, '\0', sizeof(szStrRcv));
	err = SSL_read(ssl, szStrRcv, sizeof(szStrRcv));
	szStrRcv[err] = '\0';
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "recv: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0); }

	memset(szStrRcv, '\0', sizeof(szStrRcv));
	err = SSL_read(ssl, szStrRcv, sizeof(szStrRcv));
	szStrRcv[err] = '\0';
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "recv: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0); }

	lstrcpyA(szStr, "AUTH LOGIN\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

	memset(szStrRcv, '\0', sizeof(szStrRcv));
	err = SSL_read(ssl, szStrRcv, sizeof(szStrRcv));
	szStrRcv[err] = '\0';
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "recv: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0); }


	LPSTR p;
	p = base64encode((LPBYTE)GMAIL_ACCOUNT, lstrlenA(GMAIL_ACCOUNT));
	lstrcpyA(szStr, p);
	GlobalFree(p);
	lstrcatA(szStr, "\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }
	memset(szStrRcv, '\0', sizeof(szStrRcv));
	err = SSL_read(ssl, szStrRcv, sizeof(szStrRcv));
	szStrRcv[err] = '\0';
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "recv: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0); }


	p = base64encode((LPBYTE)GMAIL_PASSWORD, lstrlenA(GMAIL_PASSWORD));
	lstrcpyA(szStr, p);
	GlobalFree(p);
	lstrcatA(szStr, "\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }
	memset(szStrRcv, '\0', sizeof(szStrRcv));
	err = SSL_read(ssl, szStrRcv, sizeof(szStrRcv));
	szStrRcv[err] = '\0';
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "recv: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0); }


	wsprintfA(szStr, "MAIL FROM: <%s>\r\n", lpszFromAddress2);
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }
	memset(szStrRcv, '\0', sizeof(szStrRcv));
	SSL_read(ssl, szStrRcv, sizeof(szStrRcv)); szStrRcv[err] = '\0';
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "recv: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0); }

	token = strtok(lpszToAddress2, ",");
	while (token)
	{
		LPSTR szText;
		szText = (PSTR)GlobalAlloc(GMEM_FIXED, lstrlenA(token) + 1);
		lstrcpyA(szText, token);

		StrTrimA(szText, " ");
		wsprintfA(szStr, "RCPT TO: <%s>\r\n", szText);
		GlobalFree(szText);

		SSL_write(ssl, szStr, lstrlenA(szStr));
		if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }
		memset(szStrRcv, '\0', sizeof(szStrRcv));
		SSL_read(ssl, szStrRcv, sizeof(szStrRcv)); szStrRcv[err] = '\0';
		if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "recv: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0); }

		token = strtok(0, ",");
	}

	lstrcpyA(szStr, "DATA\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }
	memset(szStrRcv, '\0', sizeof(szStrRcv));
	SSL_read(ssl, szStrRcv, sizeof(szStrRcv)); szStrRcv[err] = '\0';
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "recv: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0); }

	CHAR lpszSubject[1024];//ここの制限もなくしたい
	LPSTR lpTemp; lpTemp = MySJisToJis(lpszSubject2);
	if (lpTemp)
	{
		encode(lpTemp, lpszSubject);
		wsprintfA(szStr, "Subject: %s\r\n", lpszSubject);
		SSL_write(ssl, szStr, lstrlenA(szStr));
		if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }
		GlobalFree(lpTemp);
	}

	lstrcpyA(szStr, "MIME-Version: 1.0\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

	lstrcpyA(szStr, "Content-Type: multipart/mixed; boundary=\"frontier\"\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

	lstrcpyA(szStr, "\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

	lstrcpyA(szStr, "--frontier\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

	lstrcpyA(szStr, "Content-Type: text/plain; charset=shift_jis\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

	lstrcpyA(szStr, "\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

	token = strtok(lpszMessage2, "\r\n");
	while (token)
	{
		dwTextLength = lstrlenA(token);
		lpszText = (LPSTR)GlobalAlloc(GMEM_FIXED, dwTextLength + 1 + 2);
		lstrcpyA(lpszText, token);
		lstrcatA(lpszText, "\r\n");
		SSL_write(ssl, lpszText, dwTextLength + 2);
		if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), lpszText, lstrlenA(lpszText), &dwWritten, 0); }
		GlobalFree(lpszText);
		token = strtok(0, "\r\n");
	}

	for (i = 0; i<dwAttachmentCount; i++)
	{
		lstrcpyA(szStr, "--frontier\r\n");
		SSL_write(ssl, szStr, lstrlenA(szStr));
		if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

		lstrcpyA(szStr, "Content-Type: application/octet-stream\r\n");
		SSL_write(ssl, szStr, lstrlenA(szStr));
		if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

		lpTemp = MySJisToJis(PathFindFileNameA(lpszAttachment2[i]));
		if (lpTemp)
		{
			encode(lpTemp, lpszSubject);
			wsprintfA(szStr, "Content-Disposition: attachment; filename=\"%s\"\r\n", lpszSubject);
			SSL_write(ssl, szStr, lstrlenA(szStr));
			if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }
			GlobalFree(lpTemp);
		}

		lstrcpyA(szStr, "Content-Transfer-Encoding: base64\r\n");
		SSL_write(ssl, szStr, lstrlenA(szStr));
		if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

		lstrcpyA(szStr, "\r\n");
		SSL_write(ssl, szStr, lstrlenA(szStr));
		if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

		DWORD j, nLen;
		nLen = lstrlenA(lpszBase64Code[i]);
		for (j = 0; j<nLen; j += 66)
		{
			if (nLen - j>66)
			{
				CopyMemory(szStr, lpszBase64Code[i] + j, 66);
				szStr[66] = 0;
			}
			else
			{
				lstrcpyA(szStr, lpszBase64Code[i] + j);
				lstrcatA(szStr, "\r\n");
			}
			SSL_write(ssl, szStr, lstrlenA(szStr));
			if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }
		}
	}

	lstrcpyA(szStr, "--frontier--\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }

	lstrcpyA(szStr, "\x0d\x0a.\x0d\x0a");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }
	memset(szStrRcv, '\0', sizeof(szStrRcv));
	SSL_read(ssl, szStrRcv, sizeof(szStrRcv)); szStrRcv[err] = '\0';
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "recv: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0); }
	lstrcpyA(szStr, "QUIT\r\n");
	SSL_write(ssl, szStr, lstrlenA(szStr));
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "send: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStr, lstrlenA(szStr), &dwWritten, 0); }
	memset(szStrRcv, '\0', sizeof(szStrRcv));
	SSL_read(ssl, szStrRcv, sizeof(szStrRcv)); szStrRcv[err] = '\0';
	if (bLog){ WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), "recv: ", 6, &dwWritten, 0); WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), szStrRcv, lstrlenA(szStrRcv), &dwWritten, 0); }

END4:
	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ctx);
END3:
	shutdown(s, SD_BOTH);
	closesocket(s);
END2:
	for (i = 0; i<dwAttachmentCount; i++)
	{
		GlobalFree(lpszBase64Code[i]);
	}
	GlobalFree(lpszBase64Code);
END1:
	WSACleanup();
END0:
	return bRet;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPreInst, LPSTR pCmdLine, int nCmdShow)
{
	//if (argc<2)
	//{
	//	DWORD dwWritten;
	//	LPCSTR lpszUsage = "少なくとも１つの引数が必要です。\r\n";
	//	WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), lpszUsage, lstrlenA(lpszUsage), &dwWritten, 0);
	//}
	//else
	//{
	//	DWORD dwStringLength = 1;
	//	int i;
	//	for (i = 1; i<argc; i++)
	//	{
	//		dwStringLength += lstrlenA(argv[i]) + 2;
	//	}
	//	LPSTR lpszFileList = (LPSTR)GlobalAlloc(GMEM_FIXED, dwStringLength);
	//	lpszFileList[0] = 0;
	//	for (i = 1; i<argc; i++)
	//	{
	//		lstrcatA(lpszFileList, argv[i]);
	//		lstrcatA(lpszFileList, "\r\n");
	//	}
	//	SendMail(GMAIL_ACCOUNT, GMAIL_ACCOUNT, "ファイルを添付します", lpszFileList, &argv[1], argc - 1, 1);
	//	GlobalFree(lpszFileList);
	//}
	return 0;
}
