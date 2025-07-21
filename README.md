# MCT_LogServer

���� **MinecraftConnectTool** ����־�ռ�����ˣ��� .NET8 ����
���� TCP/HTTP �˿� �� ���� JSON ��־ �� �� IP ���� �� ����Ϊ�ı��ļ���

## ���  
- **�����ݿ�**����־ֱ��д�� `.txt`�������Ų顣  
- **��ƽ̨**��Windows / Linux ֱ�����е��ļ����ɡ�  
- **������**��Ĭ�ϵ� IP ÿСʱ��� 3 ���ϴ����ɸġ�  
- **֧�� Frp**������ǰ���������޹���,��ʹ��Frp,ͬʱ���� PROXY Protocol v2 ,�Ա��ȡ��ʵ�ϴ� IP��

## ������ʽ  
1. ��װ [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)��  
2. ����Ŀ��Ŀ¼ִ�У�  
   ```bash
   dotnet build -c Release
   ```  
   ��ִ���ļ��������  
   ```
   bin/Release/net8.0/LogServer(.exe)
   ```

> Visual Studio �û���ֱ�Ӵ� `.sln`���� **Build �� Build Solution** ���ɡ�

## ����  
```bash
# Windows
.\bin\Release\net8.0\LogServer.exe

# Linux
./bin/Release/net8.0/LogServer
```

�״����л��ڳ���ͬĿ¼���� `logtext/` �ļ��У�������־���ᱣ�������档  
����Ķ˿ڡ�������ֵ���Ƿ����� Frp��ֱ�Ӹ� `Program.cs` �����ļ������������� build ���ɡ�

## ��־��ʽ  
�ͻ����ϴ��� JSON �����㣺  
```json
{
  "Time": "2024-07-21T12:34:56",
  "MachineName": "DESKTOP-ABC",
  "Content": "xxxxxx"
}
```
����˻�׷��д�뵽  
```
logtext/2024-07-21-DESKTOP-ABC.txt
```
## ?? ����˵����30 ����꣩

| ���� | Ĭ��ֵ | ��; | ����ǵ� |
|---|---|---|---|
| `TcpPort` ?? | 17500 | ��־�ϴ��˿� | ���� build |
| `HttpPort` ?? | 17501 | �������˿� | ���� build |
| `EnableHttp` ? | true | �Ƿ��� HTTP ̽�� | ���� build |
| `MaxUploadPerHour` ? | 3 | �� IP ÿСʱ����ϴ�������0=���ޣ� | ���� build |
| `UseFrp` ??? | false | ��=true ���ܴ� Frp �õ���ʵ IP | ���� build |

?? **���������κ�һ�� �� ���� `dotnet build` ������Ч��**

?��������ʹ��Ai����