
# The Basics of Windows Services
Windows system services are applications that start when the computer is booted and run in the background.  Services handle 
low-level tasks that require no user interaction. There are over 200+ operating system features which implement a system service(s), to support features and functionality such as:

- Authentication, Certificate, Encryption services
- Networking features such as DNS, DHCP, Network Location Awareness, 802.11 Wireless and Wired Services.
- Hardware related services such as Plug and Play services, display driver enhancements,  audio and effects,  print services, Bluetooth 
- Remote access Terminal Services allow users to log on to a computer from a remote location.

In addition to core services that are part of Windows, third-party applications can implement device or file system drivers. Common examples of third-party services include video, sound, printing,  firewall and antivirus services.

## Services Architecture
The main components of the core service architecture are the Service Control Manager (SCM), service control programs, and service applications.  The service control programs do not communicate with services directly; all communication goes through the SCM.  This architecture is precisely what makes remote administration transparent to the service control program and service applications.
![image](images/Service%20Architecture.png)

## Service Control Manager
The SCM is a special system process that runs the image systemroot\System32\Services.exe, which is responsible for starting, stopping, and interacting with services. Services are Win32 applications that call special Win32 functions to interact with the SCM to perform such actions as registering the service’s successful startup, responding to status requests, and pausing or shutting down the service.

## Service Control Programs
Service control programs are standard Win32 applications that use the SCM APIs CreateService, OpenService, StartService, ControlService, QueryServiceStatus, and DeleteService to communicate with or control services. To use the SCM functions, a service control program must first open a communications channel to the SCM. At the time of the open call, the service control program must specify what types of actions it wants to perform. For example, if a service control program simply wants to enumerate and display the services present in the SCM database, it requests Enumerate Service access. During its initialization, the SCM creates an internal object that represents the SCM database and uses Windows security functions to protect the object with a security descriptor that specifies which accounts can open the object by using which access permissions.

The SCM stores the security descriptor in the service’s registry subkey as the Security value, and it reads the value of Security when it scans the registry’s Services key during initialization so in the same way that a service control program must specify what types of access it wants to the SCM database, a service control program must also tell the SCM what access it wants to a service. Examples of accesses that a service control program can request include the ability to query a service’s status and to configure, stop, and start a service.  For example, the security descriptor indicates that the Authenticated Users group can open the SCM object with enumerate-service access. However, only administrators can open the object with the access required to create or delete a service.

A service application contains the infrastructure necessary for communicating with the SCM, which sends commands to the service telling it to stop, pause, continue, or shut down. A service also calls special functions that communicate its status back to the SCM.   Service applications, such as Web servers, consist of at least one application that runs as a service. A user who wants to start, stop, or configure a service uses a service control program. Although Windows provides built-in service control programs that provide general start, stop, pause, and continue functionality, some service applications include their own service control program that allows administrators to specify configuration settings particular to the service they manage.

Because most services do not (and absolutely should not) have a user interface, they are built as console programs. When you install an application that includes a service, the application’s setup program must register the service with the SCM. To register the service, the setup program calls the Win32 CreateService function, a services-related function whose client side is implemented in Advapi32.dll (located in the systemroot\System32 folder). Advapi32.dll, the “Advanced API” DLL, implements all the client-side SCM APIs.

The primary difference between services and normal applications is that services are managed by the Service Control Manager (SCM). Services are implemented with the services API, which handles the interaction between the SCM and services. The SCM maintains a database of installed services and provides a unified way to control them, including:
