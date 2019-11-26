XYNTService.exe is the name of the executable for this NT service program. It is part of a client-server development tool I invented. You can freely use and modify the source code included with this article. I am now aware that there are other utility programs that provide almost the same functionality as XYNTService. However, as you will see, XYNTService has more features and it is a lot easier to use (no editing of the registry is required, for example). Here is how to use the program.

* To install the service, run the following at the command prompt: XYNTService -i
* To un-install the service, run the following at the command prompt: XYNTService -u 

By default, the installed service will be started automatically when you reboot the computer. You can also start and shutdown the service from the Control Panel using the Services icon. When the service is started, it will create all the processes you defined in the XYNTService.ini file one by one. When the service is shutdown, it will terminate each of the processes it created (in reverse order). The XYNTService.ini file should be placed in the same directory as the executable. Here is a sample of the file:

[Settings]
ServiceName = XYNTService
ProcCount = 3
CheckProcess = 30
[Process0]
CommandLine = c:\MyDir\XYRoot.exe
WorkingDir = c:\MyDir
PauseStart = 1000
PauseEnd = 1000
UserInterface = 1
Restart = 1
[Process1]
CommandLine = c:\MyDir\XYDataManager.exe
WorkingDir = c:\MyDir
PauseStart = 1000
PauseEnd = 1000
UserInterface = 1
Restart = 1
[Process2]
CommandLine= java XYRoot.XYRoot XYRootJava.ini
UserInterface = 1
Restart = 1

The ServiceName property specifies the name you want to use for this NT service, the default name is XYNTService. If you copy the executable and the .ini file into a different directory and modify the ServiceName property in the .ini file, then you can install and configure a different service!

The ProcCount property specifies how many processes you want this service to create. The sections [Process0], [Process1], ..., etc., define properties related to each of these processes. As you can see, there are 3 processes to create in this example, XYRoot.exe , XYDataManager, and java are the names of the programs, and you can specify parameters for each of these processes in the CommandLine property. You must specify the full path of the executable file for the corresponding process in the CommandLine property unless the executable is already in the system path.

The CheckProcess property specifies whether and how often you want to check processes started by XYNTService. If the property has value 0, then no checking is done. If the property value is 30, for example, then every 30 minutes XYNTService will query the operating system to see if the processes it started are still running and the dead ones will be restarted if the Restart property value (explained later) is defined to be Yes for that process. The default value of this property (if you don't specify it) is 60.

The WorkingDir property is the working directory of the current process. If you don't specify this property, then the working directory of the current process will be c:\winnt\system32. The PauseStart property is the number of milliseconds the service will wait after starting the current process (and before starting the next process). This is useful in the case where the next process depends on the previous process. For example, the second process has to "connect" to the first process so that it should not be run until the first process is finished with initialization. If you don't specify the PauseStart property, the default value will be 100 milliseconds.

When XYNTService is shutdown, it will post WM_QUIT messages to the processes it created first and then call the WIN32 function TerminateProcess. The PauseEnd property is the number of milliseconds the service will wait before TerminateProcess is called. This property can be used to give a process (started by XYNTService) a chance to clean up and shutdown itself. If you don't specify the PauseEnd property, the default value will be 100 milliseconds.

The UserInterface property controls whether a logged on user can see the processes created by XYNTService. However, this only works when XYNTService is running under the local system account, which is the default. In this case, processes created by XYNTService will not be able to access a specific user's settings (e-mail profiles, etc.). You can configure XYNTService to run under a user account, which is done easily from the Control Panel (double click the Services icon and then double click XYNTService in the installed services list to bring up a dialog box).

The Restart property is used to decided whether you want XYNTService to restart a dead process. If this property is No (which is the default if you don't specify it), then the corresponding process will not be restarted. If this property is Yes, then the dead process will be restarted by XYNTService. See the CheckProcess property above on how often dead processes are restarted.

You can bounce (stop and restart) any process defined in the .ini file from the command line. For example, the following command:

XYNTService -b 2

will stop and restart the process defined in the [Process2] section of the .ini file.

XYNTService can also be used to start and stop other services from the command line. Here are the commands to start (run) and stop (kill) other services.

XYNTService -r NameOfServiceToRun
XYNTService -k NameOfServiceToKill

In particular, you can use the above commands to start and stop XYNTService itself from command line! Please note that you cannot start XYNTService by running it from the command prompt without any argument.

All errors while running XYNTService are written into a log file in the same directory as the executable. The error code in the log file is a decimal number returned by the GetLastError API, you can look it up in MSDN.