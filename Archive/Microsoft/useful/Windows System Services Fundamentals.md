
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
